#!/usr/bin/env python3
# Created @ 2016-04-05 10:25 by @radaiming
#

import argparse
import asyncio
import fcntl
import functools
import logging
import os
import pwd
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
listen_port = 39999
redsocks_addr = ('127.0.0.1', 8123)


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


def fix_checksum(packet, bytes_src_ip, bytes_dst_ip):
    # fix IP checksum
    # https://en.wikipedia.org/wiki/IPv4#Header_Checksum
    # http://www.codeproject.com/Tips/460867/Python-Implementation-of-IP-Checksum
    ip_checksum = 0
    ip_header = packet[:10] + b'\x00\x00' + packet[12:20]
    while len(ip_header):
        ip_checksum += (ip_header[0] << 8) + ip_header[1]
        ip_header = ip_header[2:]
    ip_checksum = (ip_checksum >> 16 & 0xffff) + (ip_checksum & 0xffff)
    ip_checksum = (~ip_checksum) & 0xffff
    new_packet = packet[:10] + int(ip_checksum).to_bytes(2, 'big')

    # fix TCP checksum
    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
    # http://www.netfor2.com/tcpsum.htm
    tcp_checksum = 0
    pseudo_tcp_header = bytes_src_ip + bytes_dst_ip + b'\x00\x06'
    tcp_length = len(packet[20:]).to_bytes(2, 'big')
    pseudo_tcp_header += tcp_length
    pseudo_tcp_packet = pseudo_tcp_header + packet[20:36] + b'\x00\x00' + packet[38:]
    if len(pseudo_tcp_packet) % 2 != 0:
        pseudo_tcp_packet += b'\x00'
    while len(pseudo_tcp_packet):
        tcp_checksum += (pseudo_tcp_packet[0] << 8) + pseudo_tcp_packet[1]
        pseudo_tcp_packet = pseudo_tcp_packet[2:]
    while tcp_checksum >> 16:
        tcp_checksum = (tcp_checksum & 0xffff) + (tcp_checksum >> 16)
    tcp_checksum = (~tcp_checksum) & 0xffff

    new_packet += packet[12:36] + int(tcp_checksum).to_bytes(2, 'big') + packet[38:]
    return new_packet


def mangle_packet(packet, src_ip, src_port, dst_ip, dst_port):
    bytes_src_ip = ip_to_bytes(src_ip)
    bytes_dst_ip = ip_to_bytes(dst_ip)
    bytes_src_port = int(src_port).to_bytes(2, 'big')
    bytes_dst_port = int(dst_port).to_bytes(2, 'big') + packet[24:]
    new_packet = packet[0:12] + bytes_src_ip + bytes_dst_ip + bytes_src_port + bytes_dst_port
    return fix_checksum(new_packet, bytes_src_ip, bytes_dst_ip)


@asyncio.coroutine
def process_packet(tun, packet):
    global nat_table
    listen_ip = TUN_IP
    src_ip, src_port, dst_ip, dst_port = parse_tcp_packet(packet)
    logging.debug('%s:%s -> %s:%s' % (src_ip, src_port, dst_ip, dst_port))
    if src_ip == listen_ip and src_port == listen_port:
        new_src_ip, new_src_port = nat_table[dst_ip + ':' + dst_port].split(':')
        new_packet = mangle_packet(packet, new_src_ip, new_src_port, dst_ip, dst_port)
    else:
        nat_table[src_ip + ':' + src_port] = dst_ip + ':' + dst_port
        new_packet = mangle_packet(packet, src_ip, src_port, listen_ip, listen_port)
    tun.write(new_packet)


def handle_tun_read(tun):
    packet = tun.read(MTU)
    if packet[9:10] != b'\x06':
        logging.debug('non TCP packet received, dropping')
        return
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(process_packet(tun, packet), loop=loop)


@asyncio.coroutine
def handle_request(listen_reader, listen_writer):
    loop = asyncio.get_event_loop()
    send_reader, send_writer = yield from asyncio.open_connection(
        redsocks_addr[0], redsocks_addr[1], loop=loop)
    task_listen_reader = asyncio.ensure_future(listen_reader.read(MTU), loop=loop)
    task_send_reader = asyncio.ensure_future(send_reader.read(MTU), loop=loop)
    while True:
        done, pending = yield from asyncio.wait(
            [task_listen_reader, task_send_reader],
            return_when=asyncio.FIRST_COMPLETED
        )
        # two reader tasks may in the done at the same time
        if task_listen_reader in done:
            data = yield from task_listen_reader
            send_writer.write(data)
            yield from send_writer.drain()
            task_listen_reader = asyncio.ensure_future(listen_reader.read(MTU), loop=loop)
        if task_send_reader in done:
            data = yield from task_send_reader
            listen_writer.write(data)
            yield from listen_writer.drain()
            task_send_reader = asyncio.ensure_future(send_reader.read(MTU), loop=loop)
        if listen_reader.at_eof() or send_reader.at_eof():
            listen_writer.close()
            send_writer.close()
            break


def main():
    global redsocks_addr
    if os.getuid() != 0:
        sys.exit('please run this script as root')
    parser = argparse.ArgumentParser(description='Forward TCP packets to redsocks using TUN')
    parser.add_argument('-x', action='store', dest='redsocks_addr', default='127.0.0.1:8123',
                        help='address:port of redsocks server, default to 127.0.0.1:12345')
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
    redsocks_addr = args.redsocks_addr.split(':')
    redsocks_addr = (redsocks_addr[0], int(redsocks_addr[1]))
    try:
        tun = create_tun()
        switch_user(tun)
        loop = asyncio.get_event_loop()
        listen_coro = asyncio.start_server(handle_request, TUN_IP, listen_port, loop=loop)
        loop.run_until_complete(listen_coro)
        loop.add_reader(tun, functools.partial(handle_tun_read, tun))
        loop.run_forever()
    finally:
        loop.close()
        tun.close()


if __name__ == '__main__':
    main()
