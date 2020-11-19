import logging
import struct
import socket

ADDRTYPE_IPV4 = 0x01
ADDRTYPE_IPV6 = 0x04
ADDRTYPE_HOST = 0x03
ADDRTYPE_AUTH = 0x10
ADDRTYPE_MASK = 0xF


def parse_header(data):
    addr_type = data[0]
    dest_addr = None
    dest_port = None
    header_length = 0
    if addr_type & ADDRTYPE_MASK == ADDRTYPE_IPV4:
        dest_addr = socket.inet_ntoa(data[1:5])
        dest_port = struct.unpack('>H', data[5:7])[0]
        header_length = 7  # 1+4+2 addr_type+ipv4+port
    elif addr_type & ADDRTYPE_MASK == ADDRTYPE_HOST:
        addr_len = data[1]
        dest_addr = data[2:2 + addr_len]
        dest_port = struct.unpack('>H', data[2 + addr_len:4 + addr_len])[0]
        header_length = 4 + addr_len  # 1+2+1 addr_type port addr_len
    else:
        logging.warning('unsupported addrtype %d, maybe wrong password or encryption method' % addr_type)
    return addr_type, dest_addr, dest_port, header_length
