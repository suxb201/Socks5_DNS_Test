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
STAGE_ADDR = 1
STAGE_CONSULT = 2
# STAGE_DNS = 3
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
    def __init__(self, loop, conn, dns_resolver):
        self._dns_resolver = dns_resolver

        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []

        self._stage = STAGE_INIT

        self._remote_sock = None

        self._local_sock = conn
        self._local_sock.setblocking(False)
        self._local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        self._loop = loop
        self._loop.add(self._local_sock, eventloop.POLL_IN, self)

    def _write_to_sock(self, data, sock):
        while data:
            length = sock.send(data)
            data = data[length:]
        return True

    def _handle_stage_addr(self, data):

        cmd = int(data[1])
        if cmd == CMD_UDP_ASSOCIATE:
            logging.debug('UDP associate')
            header = b'\x05\x00\x00\x01'
            addr, port = self._local_sock.getsockname()[:2]
            addr_to_send = socket.inet_pton(self._local_sock.family, addr)
            port_to_send = struct.pack('>H', port)
            self._write_to_sock(header + addr_to_send + port_to_send, self._local_sock)
            self._stage = STAGE_UDP_ASSOC
            # just wait for the client to disconnect
            return

        if cmd != CMD_CONNECT:
            logging.error('unknown command %d', cmd)
            self.destroy()
            return

        # connect 命令
        data = data[3:]

        header_result = common.parse_header(data)

        addrtype, remote_addr, remote_port, header_length = header_result
        logging.info('connecting %s:%d from %s:%d' % (remote_addr, remote_port, self._client_address[0], self._client_address[1]))

        self._remote_address = (remote_addr, remote_port)
        # pause reading
        self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
        self._stage = STAGE_CONNECTING

        # forward address to remote
        self._write_to_sock((b'\x05\x00\x00\x01'
                             b'\x00\x00\x00\x00\x10\x10'),
                            self._local_sock)

        self._data_to_write_to_remote.append(data)
        # notice here may go into _handle_dns_resolved directly
        self._dns_resolver.resolve(self._chosen_server[0],
                                   self._handle_dns_resolved)

    def _create_remote_socket(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,
                                   socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]
        if self._forbidden_iplist:
            if common.to_str(sa[0]) in self._forbidden_iplist:
                raise Exception('IP %s is in forbidden list, reject' %
                                common.to_str(sa[0]))
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock

    def _handle_dns_resolved(self, result, error):
        pass

    def _write_to_sock_remote(self, data):
        self._write_to_sock(data, self._remote_sock)

    def _ota_chunk_data(self, data, data_cb):
        # spec https://shadowsocks.org/en/spec/one-time-auth.html
        unchunk_data = b''
        while len(data) > 0:
            if self._ota_len == 0:
                # get DATA.LEN + HMAC-SHA1
                length = ONETIMEAUTH_CHUNK_BYTES - len(self._ota_buff_head)
                self._ota_buff_head += data[:length]
                data = data[length:]
                if len(self._ota_buff_head) < ONETIMEAUTH_CHUNK_BYTES:
                    # wait more data
                    return
                data_len = self._ota_buff_head[:ONETIMEAUTH_CHUNK_DATA_LEN]
                self._ota_len = struct.unpack('>H', data_len)[0]
            length = min(self._ota_len - len(self._ota_buff_data), len(data))
            self._ota_buff_data += data[:length]
            data = data[length:]
            if len(self._ota_buff_data) == self._ota_len:
                # get a chunk data
                _hash = self._ota_buff_head[ONETIMEAUTH_CHUNK_DATA_LEN:]
                _data = self._ota_buff_data
                index = struct.pack('>I', self._ota_chunk_idx)
                key = self._encryptor.decipher_iv + index
                if onetimeauth_verify(_hash, _data, key) is False:
                    logging.warn('one time auth fail, drop chunk !')
                else:
                    unchunk_data += _data
                    self._ota_chunk_idx += 1
                self._ota_buff_head = b''
                self._ota_buff_data = b''
                self._ota_len = 0
        data_cb(unchunk_data)
        return

    def _ota_chunk_data_gen(self, data):
        data_len = struct.pack(">H", len(data))
        index = struct.pack('>I', self._ota_chunk_idx)
        key = self._encryptor.cipher_iv + index
        sha110 = onetimeauth_gen(data, key)
        self._ota_chunk_idx += 1
        return data_len + sha110 + data

    def _handle_stage_stream(self, data):
        self._write_to_sock(data, self._remote_sock)

    def _handle_stage_init(self, data):
        # 返回 00，表示无加密
        self._write_to_sock(b'\x05\00', self._local_sock)
        self._stage = STAGE_ADDR

    def _on_local_read(self):
        data = self._local_sock.recv(BUF_SIZE)

        if self._stage == STAGE_STREAM:
            self._handle_stage_stream(data)
        elif self._stage == STAGE_INIT:
            self._handle_stage_init(data)
        elif self._stage == STAGE_CONNECTING:
            self._data_to_write_to_remote.append(data)
        elif self._stage == STAGE_ADDR:
            self._handle_stage_addr(data)

    def _on_remote_read(self):
        # handle all remote read events
        data = None
        try:
            data = self._remote_sock.recv(BUF_SIZE)

        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))
        if self._is_local:
            data = self._encryptor.decrypt(data)
        else:
            data = self._encryptor.encrypt(data)
        try:
            self._write_to_sock(data, self._local_sock)
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _on_local_write(self):
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _on_remote_write(self):
        # handle remote writable event
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data, self._remote_sock)
        else:
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)

    def _on_local_error(self):
        logging.debug('got local error')
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
        self.destroy()

    def _on_remote_error(self):
        logging.debug('got remote error')
        if self._remote_sock:
            logging.error(eventloop.get_sock_error(self._remote_sock))
        self.destroy()

    def handle_event(self, sock, event):

        # order is important
        if sock == self._remote_sock:
            # if event & eventloop.POLL_ERR:
            #     self._on_remote_error()
            #     if self._stage == STAGE_DESTROYED:
            #         return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._local_sock:  # 连接

            # if event & eventloop.POLL_IN:
            self._on_local_read()

            # if event & eventloop.POLL_OUT:
            #     self._on_local_write()
        else:
            logging.warning('unknown socket')

    def destroy(self):
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            logging.debug('destroy: %s:%d' %
                          self._remote_address)
        else:
            logging.debug('destroy')
        if self._remote_sock:
            logging.debug('destroying remote')
            self._loop.remove(self._remote_sock)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)


class TCPRelay(object):
    def __init__(self, dns_resolver, loop):
        self._dns_resolver = dns_resolver
        self._loop = loop
        self._loop.add(self._server_socket, eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._loop.add_periodic(self.handle_periodic)

        listen_addr = "127.0.0.1"
        listen_port = config['listen']['port']  # socks5 监听端口

        self._fd_to_handlers = {}
        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0  # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 关闭地址复用功能
        self._server_socket.bind((listen_addr, listen_port))
        self._server_socket.setblocking(False)
        self._server_socket.listen()

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler, data_len):

        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            logging.log(shell.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler.remote_address:
                            logging.warn('timed out: %s:%d' %
                                         handler.remote_address)
                        else:
                            logging.warn('timed out')
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def handle_event(self, sock, fd, event):

        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                # TODO
                raise Exception('[tcprelay.py] server_socket error')

            conn = self._server_socket.accept()
            TCPRelayHandler(self,
                            self._fd_to_handlers,
                            self._loop,
                            conn[0],
                            self._dns_resolver)
        else:
            handler = self._fd_to_handlers.get(fd, None)
            if handler:
                handler.handle_event(sock, event)

    def handle_periodic(self):
        pass

    def close(self, next_tick=False):

        if self._loop:
            self._loop.remove_periodic(self.handle_periodic)
            self._loop.remove(self._server_socket)
        self._server_socket.close()
        for handler in list(self._fd_to_handlers.values()):
            handler.destroy()
