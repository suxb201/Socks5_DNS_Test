#!/usr/bin/python
import socket
import socks

SERVER_IP = '127.0.0.1'
SERVER_PORT = 10009

if __name__ == '__main__':
    import socket

    addr = ('127.0.0.1', 10009)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(addr)
    # while 1:
    #     data = input()
    #     if not data:
    #         break
    #     s.sendto(data.encode(), addr)

    sock_out = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
    sock_out.set_proxy(socks.SOCKS5, SERVER_IP, SERVER_PORT)
    sock_out.send(b'data')
