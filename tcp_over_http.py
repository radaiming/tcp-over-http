#!/usr/bin/env python3
# Created @ 2016-04-05 10:25 by @radaiming
# I nearly copied all logic in this article:
# http://fqrouter.tumblr.com/post/51474945203/socks%E4%BB%A3%E7%90%86%E8%BD%ACvpn#_=_
#

import argparse
import asyncio
import fcntl
import functools
import logging
import os
import pwd
import re
import struct
import subprocess
import sys

USER = 'nobody'
GROUP = 'nobody'
TUN_IP = '10.45.39.1'
NETMASK = 24
MTU = 1500
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETOWNER = TUNSETIFF + 2
nat_table = {}
fake_src_ip = '10.45.39.3'
listen_ip = TUN_IP
listen_port = 39999
proxy_addr = ('127.0.0.1', 8123)


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
    subprocess.call(str.split('ip addr add %s/%d dev %s' % (TUN_IP, NETMASK, name)))
    subprocess.call(str.split('ip link set %s up' % name))
    subprocess.call(str.split('ip link set dev %s mtu %d' % (name, MTU)))
    logging.info('%s: %s/%d' % (name, TUN_IP, NETMASK))
    return tun


def parse_tcp_packet(packet):
    src_ip = '%d.%d.%d.%d' % tuple(list(packet[12:16]))
    dst_ip = '%d.%d.%d.%d' % tuple(list(packet[16:20]))
    src_port = str((packet[20] << 8) + packet[21])
    dst_port = str((packet[22] << 8) + packet[23])
    return src_ip, src_port, dst_ip, dst_port


def ip_to_bytes(ip):
    bytes_ip = b''
    for i in map(int, ip.split('.')):
        bytes_ip += bytes([i])
    return bytes_ip


def mangle_packet(packet, src_ip, src_port, dst_ip, dst_port):
    bytes_src_ip = ip_to_bytes(src_ip)
    bytes_dst_ip = ip_to_bytes(dst_ip)
    bytes_src_port = int(src_port).to_bytes(2, 'big')
    bytes_dst_port = int(dst_port).to_bytes(2, 'big')

    new_addr_checksum = 0
    new_addr_checksum += (bytes_src_ip[0] << 8) + bytes_src_ip[1]
    new_addr_checksum += (bytes_src_ip[2] << 8) + bytes_src_ip[3]
    new_addr_checksum += (bytes_dst_ip[0] << 8) + bytes_dst_ip[1]
    new_addr_checksum += (bytes_dst_ip[2] << 8) + bytes_dst_ip[3]
    new_port_checksum = 0
    new_port_checksum += (bytes_src_port[0] << 8) + bytes_src_port[1]
    new_port_checksum += (bytes_dst_port[0] << 8) + bytes_dst_port[1]

    old_addr_checksum = 0
    old_port_checksum = 0
    i = 12
    while i < 20:
        old_addr_checksum += (packet[i] << 8) + packet[i+1]
        i += 2
    while i < 24:
        old_port_checksum += (packet[i] << 8) + packet[i+1]
        i += 2

    old_ip_checksum = (packet[10] << 8) + packet[11]
    delta = new_addr_checksum - old_addr_checksum
    abs_delta = abs(delta)
    if delta > 0:
        ip_checksum = old_ip_checksum - abs_delta
    else:
        ip_checksum = old_ip_checksum + abs_delta
    while ip_checksum >> 16:
        ip_checksum = (ip_checksum >> 16) + (ip_checksum & 0xffff)

    old_tcp_checksum = (packet[36] << 8) + packet[37]
    new_addr_port_checksum = new_addr_checksum + new_port_checksum
    delta = new_addr_port_checksum - (old_addr_checksum + old_port_checksum)
    abs_delta = abs(delta)
    if delta > 0:
        tcp_checksum = old_tcp_checksum - abs_delta
    else:
        tcp_checksum = old_tcp_checksum + abs_delta
    while tcp_checksum >> 16:
        tcp_checksum = (tcp_checksum >> 16) + (tcp_checksum & 0xffff)

    new_packet = packet[:10] + int(ip_checksum).to_bytes(2, 'big') +\
        bytes_src_ip + bytes_dst_ip + bytes_src_port + bytes_dst_port +\
        packet[24:36] + int(tcp_checksum).to_bytes(2, 'big') + packet[38:]
    return new_packet


def handle_tun_read(tun):
    global nat_table
    packet = tun.read(MTU)
    if packet[9:10] != b'\x06':
        logging.debug('non TCP packet received, dropping')
        return
    src_ip, src_port, dst_ip, dst_port = parse_tcp_packet(packet)
    logging.debug('read packet from tun: %s:%s -> %s:%s' % (src_ip, src_port, dst_ip, dst_port))
    if src_ip == listen_ip and src_port == str(listen_port):
        try:
            new_src_ip, new_src_port = nat_table[dst_ip + ':' + dst_port][1:]
        except KeyError:
            # when restarting this program, some old packet may come in
            return
        new_dst_ip = nat_table[dst_ip + ':' + dst_port][0]
        new_packet = mangle_packet(packet, new_src_ip, new_src_port, new_dst_ip, dst_port)
        logging.debug('write new packet to tun: %s:%s -> %s:%s' % (new_src_ip, new_src_port, new_dst_ip, dst_port))
    else:
        nat_table[fake_src_ip + ':' + src_port] = (src_ip, dst_ip, dst_port)
        new_packet = mangle_packet(packet, fake_src_ip, src_port, listen_ip, listen_port)
        logging.debug('write new packet to tun: %s:%s -> %s:%s' % (fake_src_ip, src_port, listen_ip, listen_port))
    tun.write(new_packet)


@asyncio.coroutine
def handle_request(listen_reader, listen_writer):
    local_peer = listen_writer.transport.get_extra_info('peername')
    # avoid exception if someone else directly send request to here
    if ('%s:%d' % local_peer) not in nat_table:
        listen_writer.close()
        return
    loop = asyncio.get_event_loop()
    try:
        send_reader, send_writer = yield from asyncio.open_connection(
            proxy_addr[0], proxy_addr[1], loop=loop, local_addr=('127.0.0.1', 0))
        target_addr = nat_table[('%s:%d' % local_peer)][1:]
        logging.debug('%s:%d -> %s:%s: connected to proxy server' % (local_peer + target_addr))
        conn_msg = 'CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n' % (target_addr * 2)
        conn_bytes = conn_msg.encode('ascii')
        send_writer.write(conn_bytes)
        data = yield from send_reader.read(MTU)
        ret = re.match('HTTP/\d\.\d\s+?(\d+?)\s+?', data.decode('ascii', 'ignore'))
        if not ret:
            status_code = 'unknown'
        else:
            status_code = ret.groups()[0]
        if status_code != '200':
            err_msg = 'failed to connect to proxy server: ' + status_code
            logging.error(err_msg)
            listen_writer.write(err_msg.encode('ascii', 'ignore'))
            listen_writer.close()
            send_writer.close()
            return
    except ConnectionRefusedError:
        logging.error('proxy server refused our connection')
        listen_writer.close()
        return
    task_listen_reader = asyncio.ensure_future(listen_reader.read(MTU), loop=loop)
    task_send_reader = asyncio.ensure_future(send_reader.read(MTU), loop=loop)
    while True:
        try:
            done, pending = yield from asyncio.wait(
                [task_listen_reader, task_send_reader],
                return_when=asyncio.FIRST_COMPLETED
            )
            # two reader tasks may in the done at the same time
            if task_listen_reader in done:
                logging.debug('from %s:%d: get data from listen_reader' % local_peer)
                data = yield from task_listen_reader
                send_writer.write(data)
                yield from send_writer.drain()
                task_listen_reader = asyncio.ensure_future(listen_reader.read(MTU), loop=loop)
            if task_send_reader in done:
                logging.debug('from %s:%d: get data from send reader' % local_peer)
                data = yield from task_send_reader
                listen_writer.write(data)
                yield from listen_writer.drain()
                task_send_reader = asyncio.ensure_future(send_reader.read(MTU), loop=loop)
            if listen_reader.at_eof() or send_reader.at_eof():
                logging.debug('from %s:%d: finish rw, now exit' % local_peer)
                listen_writer.close()
                send_writer.close()
                break
        except (ConnectionResetError, BrokenPipeError) as exp:
            logging.error('error on connecting to %s:%s: ' % target_addr + str(exp))
            listen_writer.close()
            send_writer.close()
            break


def main():
    global proxy_addr
    if os.getuid() != 0:
        sys.exit('please run this script as root')
    parser = argparse.ArgumentParser(description='Forward TCP packets to HTTP proxy using TUN')
    parser.add_argument('-x', action='store', dest='proxy_addr', default='127.0.0.1:8123',
                        help='address:port of proxy server, default to 127.0.0.1:12345')
    parser.add_argument('--debug', action='store_true', dest='debug', default=False,
                        help='enable debug outputing')
    args = parser.parse_args(sys.argv[1:])
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.WARNING
    logging.basicConfig(level=logging_level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    proxy_addr = args.proxy_addr.split(':')
    proxy_addr = (proxy_addr[0], int(proxy_addr[1]))
    try:
        tun = create_tun()
        switch_user(tun)
        loop = asyncio.get_event_loop()
        listen_coro = asyncio.start_server(handle_request, listen_ip, listen_port, loop=loop)
        loop.run_until_complete(listen_coro)
        loop.add_reader(tun, functools.partial(handle_tun_read, tun))
        loop.run_forever()
    finally:
        loop.close()
        tun.close()


if __name__ == '__main__':
    main()
