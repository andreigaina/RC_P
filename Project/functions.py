import enum
import socket
import struct
import time

import netifaces

_MDNS_PORT = 5353
_MDNS_ADDR = '224.0.0.251'

def current_time_millis():
    """Current system time in milliseconds"""
    return time.time() * 1000


@enum.unique
class InterfaceChoice(enum.Enum):
    Default = 1
    All = 2


def get_all_addresses(address_family):
    return [
        addr['addr']
        for iface in netifaces.interfaces()
        for addr in netifaces.ifaddresses(iface).get(address_family, [])
    ]


def normalize_interface_choice(choice, address_family):
    if choice is InterfaceChoice.Default:
        choice = ['0.0.0.0']
    elif choice is InterfaceChoice.All:
        choice = get_all_addresses(address_family)
    return choice


def new_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # More than one process needs to bind to the same SOCK_DGRAM port =>
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Unrestricted in scope
    ttl = struct.pack(b'B', 255)
    loop = struct.pack(b'B', 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    # Enable loopback
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
    s.bind(('', _MDNS_PORT))
    return s


def send(out_, addr=_MDNS_ADDR, port=_MDNS_PORT):
    packet = out_.packet()
    socket_ = new_socket()
    bytes_sent = socket_.sendto(packet, (addr, port))
    # print(len(packet))
    if bytes_sent != len(packet):
        raise Exception(
            'Sent %d out of %d bytes!' % (bytes_sent, len(packet)))
