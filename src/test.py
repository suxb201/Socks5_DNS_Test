# with open("config.toml", encoding='utf-8') as f:
#     config = toml.loads(f.read())
# print(config)
# x = datetime.now().timestamp()
# time.sleep(3)
# y = datetime.now().timestamp()
# print(y-x)
import socket

# addresses = socket.getaddrinfo(
#     "127.0.0.1",
#     10009,
#     0,
#     socket.SOCK_DGRAM,
#     socket.SOL_UDP
# )
# socket_family, socket_type, socket_proto, socket_name, socket_addr = addresses[0]
# print(addresses)
# print(socket.AF_INET)
ADDRTYPE_MASK = 0xF
print(type(ADDRTYPE_MASK))