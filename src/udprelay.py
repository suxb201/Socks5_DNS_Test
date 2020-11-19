# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+


from __future__ import absolute_import, division, print_function, with_statement

import logging
import socket
import struct

import common
import eventloop
from config import config

BUF_SIZE = 65536


# # af ???
# # 返回一个 key 做 cache
# def client_key(source_addr, server_af):
#     # notice this is server af, not dest af
#     # 跳板机ip  不是目的地址ip
#     return '%s:%s:%d' % (source_addr[0], source_addr[1], server_af)


def pack_addr(address):
    r = socket.inet_pton(socket.AF_INET, address)
    return b'\x01' + r


class UDPRelay(object):
    def __init__(self, dns_resolver, loop):
        self._browser_addr = None

        listen_addr = "127.0.0.1"
        listen_port = config['listen']['port']  # socks5 监听端口

        self._local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._local_socket.bind((listen_addr, listen_port))
        self._local_socket.setblocking(False)

        self._remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._remote_socket.setblocking(False)

        self._loop = loop
        self._loop.add(self._local_socket, eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._loop.add(self._remote_socket, eventloop.POLL_IN, self)
        self._loop.add_periodic(self.handle_periodic)

        logging.info(f"UDP bind: {listen_addr} {listen_port}")

    # 处理浏览器发来的信息，这个 socket 是用来监听 10007 的
    # browser -> unpack -> internet
    def _on_local_read(self):

        data, self._browser_addr = self._local_socket.recvfrom(BUF_SIZE)  # data, addr

        if not data:
            logging.debug('UDP handle_server: data is empty')

        # 对于序列化帧的实现是可选的；如果一个实现不支持，则应当丢弃任何 FRAG 字段值不为 X‘00’ 的数据包。
        if int(data[2]) != 0:
            logging.warning('UDP drop a message since FRAG is not 0.')
            return
        else:
            data = data[3:]

        # data 现在是 payload
        # 假设：data 是 socks5 类型的，所以才能方便处理 header
        addr_type, dest_addr, dest_port, header_length = common.parse_header(data)

        # TODO: 需要加上 DNS 解析
        # dest_addr hostname or ip -> ip

        data = data[header_length:]

        self._remote_socket.sendto(data, (dest_addr, dest_port))

    # internet -> pack -> 浏览器
    def _on_remote_read(self, sock):
        data, (addr, port) = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return

        data = b'\x00\x00\x00' + pack_addr(addr) + struct.pack('>H', port) + data

        self._local_socket.sendto(data, self._browser_addr)

    def handle_event(self, sock, fd, event):
        if sock == self._local_socket:  # listen port
            if event & eventloop.POLL_ERR:
                logging.error('UDP server_socket err')
            self._on_local_read()
        elif sock == self._remote_socket:
            if event & eventloop.POLL_ERR:
                logging.error('UDP client_socket err')
            self._on_remote_read(sock)

    def handle_periodic(self):
        pass

    def close(self):
        logging.debug('UDP close')

        if self._loop:
            self._loop.remove_periodic(self.handle_periodic)
            self._loop.remove(self._local_socket)
            self._loop.remove(self._remote_socket)
        self._local_socket.close()
        self._remote_socket.close()
