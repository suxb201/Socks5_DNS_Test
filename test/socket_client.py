#!/usr/bin/env python3

import socket

HOST = '127.0.0.1'  # 服务器的主机名或者 IP 地址
PORT = 10009  # 服务器使用的端口

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(s)
    s.connect((HOST, PORT))
    s.sendall(b'Hello, world')
    print(s)
    data = s.recv(1024)

print('Received', repr(data))
