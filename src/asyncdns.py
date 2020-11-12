# async dns

import os
import re
import socket
import struct
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, unique
from typing import Dict, Callable, Set, List

import ping3

import eventloop
from config import config

VALID_HOSTNAME = re.compile(r"(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1


class DNSPackage:
    @staticmethod
    def build_req(hostname, req_id):  # hostname qtype
        header = req_id + struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)  # B 一个字节 H 两个字节
        question = DNSPackage._build_question(hostname) + struct.pack('!HH', QTYPE_A, QCLASS_IN)
        return header + question

    @staticmethod
    def parse_res(data):
        header = DNSPackage._parse_header(data)

        res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, res_ancount, res_nscount, res_arcount = header

        questions = []
        answers = []
        offset = 12
        for i in range(0, res_qdcount):
            length, res = DNSPackage._parse_record(data, offset, True)
            offset += length
            questions.append(res)
        for i in range(0, res_ancount):
            length, res = DNSPackage._parse_record(data, offset)
            offset += length
            if res is not None:
                answers.append(res)

        return res_id, questions[0], answers

    @staticmethod
    def _build_question(hostname):
        labels = hostname.split('.')  # 分割
        results = []
        for label in labels:
            results.append(bytes([len(label)]))  # 长度
            results.append(label.encode(encoding="utf-8"))  # 域名
        results.append(b'\0')
        return b''.join(results)

    @staticmethod
    def _parse_ip(addrtype, data, length, offset):
        # TODO:这里只处理了 type a
        if addrtype == QTYPE_A:
            return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])

    # 解析域名
    @staticmethod
    def _parse_name(data, offset):
        p = offset
        labels = []
        length = int(data[p])
        while length > 0:
            if (length & (128 + 64)) == (128 + 64):
                # pointer
                pointer = struct.unpack('!H', data[p:p + 2])[0]
                pointer &= 0x3FFF
                r = DNSPackage._parse_name(data, pointer)
                labels.append(r[1])
                p += 2
                # pointer is the end
                return p - offset, '.'.join(labels)
            else:
                labels.append(data[p + 1:p + 1 + length].decode('utf-8'))
                p += 1 + length
            length = int(data[p])
        return p - offset + 1, '.'.join(labels)

    @staticmethod
    def _parse_record(data, offset, question=False):
        nlen, name = DNSPackage._parse_name(data, offset)
        if not question:  # 答案区域
            record_type, record_class, record_ttl, record_rdlength = struct.unpack(
                '!HHiH', data[offset + nlen:offset + nlen + 10]
            )
            ip = DNSPackage._parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
            return nlen + 10 + record_rdlength, ip
        else:
            return nlen + 4, name

    @staticmethod
    def _parse_header(data):
        if len(data) >= 12:  # header 为 12 个字节，也就是 32bits * 3=4Bytes * 3=12Bytes
            header = struct.unpack('!HBBHHHH', data[:12])
            res_id = header[0]
            res_qr = header[1] & 128
            res_tc = header[1] & 2
            res_ra = header[2] & 128
            res_rcode = header[2] & 15
            # assert res_tc == 0
            # assert res_rcode in [0, 3]
            res_qdcount = header[3]
            res_ancount = header[4]
            res_nscount = header[5]
            res_arcount = header[6]

            return res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, res_ancount, res_nscount, res_arcount
        return None


def is_valid_hostname(hostname):
    if len(hostname) > 255 or len(hostname) == 0:
        return False
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split('.'))


@dataclass
class DNSResponse:
    req_id: bytes
    hostname: str
    ip_list: List[str]


@unique
class STATUS(Enum):
    INIT = 1
    RUNNING = 2
    FINISH = 3


class Item:
    def __init__(self, hostname):
        self.hostname = hostname
        self.status = STATUS.INIT  # 0: 刚初始化，1：在跑，2：已跑出结果
        self.ip: str = ""
        self.count: int = 0
        self.callbacks: List[Callable] = []
        self.timestamp: float = 0

        self.ip_to_nameserver: Dict[str, Set[str]] = {}
        self.ip_to_latency: Dict[str, float] = {}

    def is_fresh(self) -> bool:
        if datetime.now().timestamp() - self.timestamp > config['dns']['cache_time']:
            return False
        return True

    def calc_fastest_ip(self):
        self.timestamp = datetime.now().timestamp()
        min_latency = 999999
        self.ip = None
        for k, v in self.ip_to_nameserver.items():

            try:
                tmp_len = ping3.ping(k, timeout=1)
            except OSError:
                tmp_len = None
            if tmp_len is None:
                tmp_len = 999999
            if k not in self.ip_to_latency:
                self.ip_to_latency[k] = round(tmp_len * 1000, 2)
            else:
                self.ip_to_latency[k] = self.ip_to_latency[k] + round(tmp_len * 1000, 2)
                self.ip_to_latency[k] /= 2
                self.ip_to_latency[k] = round(self.ip_to_latency[k], 2)
            if min_latency >= self.ip_to_latency[k]:
                min_latency = self.ip_to_latency[k]
                self.ip = k
        if self.ip is None:
            print(f"{self.hostname:15}: fk GFW")
        else:
            print(f"{self.hostname:15}: best ip: {self.ip}, latency: {self.ip_to_latency[self.ip]}")


def _call_cb(callback, ip):
    if ip is None:
        callback(None, "gfw")
    else:
        callback(ip, None)


class DNSResolver(object):

    def __init__(self, loop):

        self._hosts: Dict[str, Item] = dict()
        self._id_to_nameserver: Dict[int, dict] = dict()
        # ---- loop ----
        self._loop = loop  # 主循环
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
        self._socket.setblocking(False)
        loop.add(self._socket, eventloop.POLL_IN, self)
        loop.add_periodic(self.handle_periodic)

    # 处理 nameserver 返回的数据
    def _handle_data(self, data):
        req_id, hostname, ip_list = DNSPackage.parse_res(data)
        if req_id not in self._id_to_nameserver:
            return

        item = self._hosts[hostname]
        item.count -= 1

        nameserver = self._id_to_nameserver[req_id]

        # print(ip_list)
        for ip in ip_list:
            if ip not in item.ip_to_nameserver:
                item.ip_to_nameserver[ip] = set()
            item.ip_to_nameserver[ip].add(nameserver['describe'])

        del self._id_to_nameserver[req_id]

        if item.count == 0:
            item.status = STATUS.FINISH
            item.calc_fastest_ip()
            for callback in item.callbacks:
                # callback(item.ip, None)
                _call_cb(callback, item.ip)
            item.callbacks = []

    def handle_event(self, sock, fd, event):

        data, addr = sock.recvfrom(1024)
        self._handle_data(data)

    def handle_periodic(self):
        with open('hosts', 'w', encoding='utf-8') as f:
            for k, item in self._hosts.items():
                if item.ip:
                    f.write(f"{item.ip:<15} {k:<23} # {item.ip_to_latency[item.ip]:>6}ms, {item.ip_to_nameserver[item.ip]}\n")
        # print("hosts saved!")

        # def make_callback():  # 返回一个 callback
        #
        #     def callback(result, error):
        #         pass
        #         # print(result, error)
        #
        #     a_callback = callback
        #     return a_callback
        #
        # hostname = input("input hostname: ")
        # self.resolve(hostname, make_callback())

    def _send_req(self, nameserver, hostname):
        req_id = os.urandom(2)  # 无符号 2 个字节 = 16bit
        self._id_to_nameserver[int.from_bytes(req_id, "big")] = nameserver
        req = DNSPackage.build_req(hostname, req_id)  # TODO: 添加回调函数
        self._socket.sendto(req, (nameserver['ip'], 53))

    def resolve(self, hostname, callback):
        # 如果是无效域名
        if not is_valid_hostname(hostname):
            callback(None, Exception(f'invalid hostname:{hostname}'))
            return

        if hostname not in self._hosts:
            self._hosts[hostname] = Item(hostname)

        item = self._hosts[hostname]

        if item.status == STATUS.INIT:
            for nameserver in config['dns']['nameserver']:
                self._send_req(nameserver, hostname)
                item.count += 1
            item.status = STATUS.RUNNING

        if item.status == STATUS.RUNNING:
            item.callbacks.append(callback)

        if item.status == STATUS.FINISH:
            if item.is_fresh():
                print(f"{hostname}: hit cache")
                _call_cb(callback, item.ip)
            else:
                # 重新来过
                for nameserver in config['dns']['nameserver']:
                    self._send_req(nameserver, hostname)
                    item.count += 1
                item.status = STATUS.RUNNING

    def close(self):
        if self._socket:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._socket)
            self._socket.close()
            self._socket = None


def test():
    loop = eventloop.EventLoop()  # 创建 loop 实例
    dns_resolver = DNSResolver(loop)  # 创建实例

    def make_callback():  # 返回一个 callback

        def callback(result, error):
            pass
            # print(result, error)

        a_callback = callback
        return a_callback

    assert (make_callback() != make_callback())

    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('baidu.com', make_callback())
    dns_resolver.resolve('i0.hdslb.com', make_callback())
    # dns_resolver.resolve('bstatic.hdslb.com', make_callback())
    # dns_resolver.resolve('s1.hdslb.com.w.kunlunar.com', make_callback())
    loop.run()  # rua！

    # dns_resolver.close()
    # loop.stop()


if __name__ == '__main__':
    test()
