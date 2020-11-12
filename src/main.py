import logging
import os
import signal
import sys

import asyncdns
import eventloop
import udprelay


def main():
    loop = eventloop.EventLoop()
    dns_resolver = asyncdns.DNSResolver(loop)
    # tcp_server = tcprelay.TCPRelay(dns_resolver, loop)
    udp_server = udprelay.UDPRelay(dns_resolver, loop)

    def handler(signum, _):
        logging.warning('received SIGQUIT, doing graceful shutting down..')
        # tcp_server.close(next_tick=True)
        udp_server.close()

    signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

    def int_handler(signum, _):
        sys.exit(1)

    signal.signal(signal.SIGINT, int_handler)

    loop.run()


if __name__ == '__main__':
    print(os.path.dirname(__file__))
    main()
