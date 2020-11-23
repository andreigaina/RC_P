import socket
import time

_MDNS_PORT = 5353

def current_time_millis():
    """Current system time in milliseconds"""
    return time.time() * 1000


def new_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # More than one process needs to bind to the same SOCK_DGRAM port =>
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Unrestricted in scope
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    # Enable loopback
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    s.bind(('', _MDNS_PORT))