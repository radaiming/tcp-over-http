#!/usr/bin/env python3
# Created @ 2016-04-05 10:25 by @radaiming
#

import asyncio
import fcntl
import functools
import logging
import os
import pwd
import re
import socket
import struct
import subprocess
import sys

USER = 'nobody'
GROUP = 'nobody'
IP = '10.45.39.1'
NETMASK = 24
MTU = 1500
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETOWNER = TUNSETIFF + 2
DEBUG = True
PROXY_SERVER = ('127.0.0.1', 7070)
listen_server_nat_map = {}


class SendProtocol(asyncio.Protocol):
    def __init__(self, transport, remote_peer, block_queue):
        self.transport = None
        # use listen_transport to send data back
        self.listen_transport = transport
        # a (host, port) tuple
        self.remote_peer = remote_peer
        self.block_queue = block_queue

    def connection_made(self, transport):
        self.transport = transport
        # start HTTP CONNECT
        conn_str = 'CONNECT %s:%d HTTP/1.1\r\nAccept: */*\r\n\r\n' % self.remote_peer
        self.transport.write(conn_str.encode('ascii'))

    def data_received(self, data):
        if not self.block_queue.empty():
            # HTTP CONNECT not finished, this is response from proxy server
            yield from self.block_queue.get()
            # unblock the 'yield from' in ListenProtocol
            self.block_queue.task_done()
            data_str = data.decode('ascii', 'ignore')
            ret = re.match('HTTP/\d\.\d\s+?(\d+?)\s+?', data_str)
            if not ret or ret.group()[0] != '200':
                logging.error('failed to connect to proxy server: ' + data_str)
                self.transport.close()
                self.listen_transport.close()
        else:
            # the real data we want
            self.listen_transport.write(data)


class ListenProtocol(asyncio.Protocol):
    """
    listen for forwarded packet, then call SendProtocol
    to send them to proxy server
    """
    def __init__(self):
        self.transport = None
        # use send_transport to send data to proxy server
        self.send_transport = None
        # will be used in SendProtocol
        self.remote_peer = None
        self.loop = asyncio.get_event_loop()
        # we need to block all request until HTTP CONNECT success
        self.block_queue = asyncio.Queue(self.loop)
        self.block_queue.put('x')

    def connection_made(self, transport):
        self.transport = transport
        self.remote_peer = transport.get_extra_info('peername')

    def data_received(self, data):
        # NAT map is not needed here, each connection
        # will have an individual coroutine
        if self.send_transport is None:
            server, port = PROXY_SERVER
            # create TCP connection to proxy server
            self.send_transport, _ = yield from self.loop.create_connection(
                lambda: SendProtocol(self.transport, self.remote_peer, self.block_queue),
                server, port)
        # block until HTTP CONNECT success
        # FIXME: if SendProtocol failed before proxy server response, will block here forever?
        yield from self.block_queue.join()
        self.send_transport.write(data)


class ForwardProtocol(asyncio.Protocol):
    """
    forward packet to ListenProtocol, let it
    handle the whole TCP details
    """
    pass


def switch_user(tun):
    # switch to non privileged user for security
    target_uid = pwd.getpwnam(USER).pw_uid
    fcntl.ioctl(tun.fileno(), TUNSETOWNER, target_uid)
    os.setuid(target_uid)


def create_tun():
    # ref:
    # https://www.kernel.org/doc/Documentation/networking/tuntap.txt
    # https://github.com/Gawen/pytun/blob/master/pytun.py
    # https://cocotb.readthedocs.org/en/latest/ping_tun_tap.html
    # https://github.com/montag451/pytun/blob/master/pytun.c
    # https://github.com/stefanholek/term/issues/1#issuecomment-5338409
    tun = open('/dev/net/tun', 'r+b', buffering=0)
    ret = fcntl.ioctl(tun, TUNSETIFF, struct.pack('16sH', b'', IFF_TUN | IFF_NO_PI))
    name = ret[:16].strip(b'\x00').decode('ascii')
    # not nice enough? but much easier than calling ioctl
    subprocess.call(str.split('ip addr add %s/%d dev %s' % (IP, NETMASK, name)))
    subprocess.call(str.split('ip link set %s up' % name))
    subprocess.call(str.split('ip link set dev %s mtu %d' % (name, MTU)))
    logging.info('%s: %s/%d' % (name, IP, NETMASK))
    return tun


@asyncio.coroutine
def process_packet(packet, listen_port):
    # modify the packet; then use ForwardProtocol to send
    print(hex(packet[9]))


def handle_read(tun, listen_port):
    packet = tun.read(MTU)
    if packet[9:10] != b'\x06':
        logging.debug('non TCP packet received, dropping')
        return
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(process_packet(packet, listen_port), loop=loop)


def main():
    if os.getuid() != 0:
        sys.exit('please run this script as root')
    if DEBUG:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.WARNING
    logging.basicConfig(level=logging_level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    try:
        tun = create_tun()
        switch_user(tun)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((IP, 0))
        _, listen_port = sock.getsockname()

        loop = asyncio.get_event_loop()
        listen_coro = loop.create_connection(ListenProtocol, sock=sock)
        asyncio.ensure_future(listen_coro)
        loop.add_reader(tun, functools.partial(handle_read, tun, listen_port))
        loop.run_forever()
    finally:
        loop.close()
        tun.close()


if __name__ == '__main__':
    main()
