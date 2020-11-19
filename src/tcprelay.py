import time
import socket
import errno
import struct
import logging
import traceback
import random

import common
from config import config
import eventloop

# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2  # TODO：支持 bind 命令
CMD_UDP_ASSOCIATE = 3

STAGE_INIT = 0
STAGE_CONSULT = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024


class TCPRelayHandler(object):
    def __init__(self, conn, loop):
        # self._dns_resolver = dns_resolver

        self._stage = STAGE_INIT

        self._remote_sock = None

        self._local_sock = conn
        self._local_sock.setblocking(False)
        self._local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        self._loop = loop
        self._loop.add(self._local_sock, eventloop.POLL_IN, self)

        self._remote_addr = None
        self._remote_port = None
        self._local_addr = "127.0.0.1"
        self._local_port = config["listen"]["port"]

    @staticmethod
    def _write_to_sock(data, sock):
        while data:
            length = sock.send(data)
            data = data[length:]

    def _handle_stage_consult(self, data):

        cmd = int(data[1])
        if cmd == CMD_UDP_ASSOCIATE:
            logging.debug('UDP associate')
            header = b'\x05\x00\x00\x01'
            addr, port = self._local_sock.getsockname()[:2]
            addr_to_send = socket.inet_pton(self._local_sock.family, addr)
            port_to_send = struct.pack('>H', port)
            self._write_to_sock(header + addr_to_send + port_to_send, self._local_sock)
            self._stage = STAGE_UDP_ASSOC  # 切换到 UDP
            # just wait for the client to disconnect
            return

        if cmd != CMD_CONNECT:
            logging.error('unknown command %d', cmd)
            self.destroy()
            return

        # connect 命令
        data = data[3:]

        addrtype, self._remote_addr, self._remote_port, header_length = common.parse_header(data)

        logging.info('connecting %s:%d from %s:%d' % (self._remote_addr, self._remote_port, self._local_addr, self._local_port))

        # 答复浏览器，socks5 握手结束
        self._write_to_sock(b'\x05\x00\x00\x01'
                            b'\x00\x00\x00\x00\x10\x10',
                            self._local_sock)

        # create remote sock
        self._remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self._remote_sock.setblocking(True)

        self._remote_sock.connect((self._remote_addr, self._remote_port))
        self._loop.add(self._remote_sock, eventloop.POLL_IN, self)

        # 剩下的数据发送到 remote sock
        self._write_to_sock(data, self._remote_sock)

        self._stage = STAGE_CONNECTING

    def _handle_stage_init(self):
        # 返回 00，表示无加密
        self._write_to_sock(b'\x05\00', self._local_sock)
        self._stage = STAGE_CONSULT

    def _on_local_read(self):
        data = self._local_sock.recv(BUF_SIZE)
        # STAGE_INIT -> STAGE_CONSULT -> STAGE_CONNECTING
        if self._stage == STAGE_INIT:
            self._handle_stage_init()
        elif self._stage == STAGE_CONSULT:
            self._handle_stage_consult(data)
        elif self._stage == STAGE_CONNECTING:
            self._write_to_sock(data, self._remote_sock)

    def _on_remote_read(self):

        data = self._remote_sock.recv(BUF_SIZE)
        self._write_to_sock(data, self._local_sock)

    def handle_event(self, sock, fd, event):

        # order is important
        if sock == self._remote_sock:
            if event & eventloop.POLL_IN:
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            else:
                logging.warning('_remote_sock unknown event')
        elif sock == self._local_sock:  # 连接

            if event & eventloop.POLL_IN:
                self._on_local_read()
            else:
                logging.warning('_local_sock unknown event')
        else:
            logging.warning('unknown socket')

    def destroy(self):
        self._stage = STAGE_DESTROYED
        logging.debug('destroy')
        if self._remote_sock:
            logging.debug('destroying remote')
            self._loop.remove(self._remote_sock)
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            self._local_sock.close()
            self._local_sock = None


class TCPRelay(object):
    def __init__(self, dns_resolver, loop):
        self._dns_resolver = dns_resolver

        listen_addr = "127.0.0.1"
        listen_port = config['listen']['port']  # socks5 监听端口

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 关闭地址复用功能
        self._server_socket.bind((listen_addr, listen_port))
        self._server_socket.setblocking(False)
        self._server_socket.listen()

        self._loop = loop
        self._loop.add(self._server_socket, eventloop.POLL_IN, self)
        self._loop.add_periodic(self.handle_periodic)

    def handle_event(self, sock, fd, event):
        if sock == self._server_socket:
            conn, addr = self._server_socket.accept()
            TCPRelayHandler(conn,
                            self._loop)
        else:
            logging.warning(f"[handle_event] sock!=self.server_socket")

    def handle_periodic(self):
        pass

    def close(self):
        if self._loop:
            self._loop.remove_periodic(self.handle_periodic)
            self._loop.remove(self._server_socket)
        self._server_socket.close()
