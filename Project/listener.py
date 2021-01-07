

from dnsIncoming import *
from queryTypes import *
import queryTypes


class Listener:
    def __init__(self, zeroconf):
        self.zeroconf = zeroconf
        self.data = None

    def handle_read(self, socket_):
        try:
            data, (addr, port) = socket_.recvfrom(queryTypes._MAX_MSG_ABSOLUTE)
        except socket.error as err:
            if err.errno == socket.EBADF:
                return
            else:
                raise err
        self.data = data
        msg = DNSIncoming(data)
        if msg.is_query():
            if port == queryTypes._MDNS_PORT:
                self.zeroconf.handle_query(msg, queryTypes._MDNS_ADDR, queryTypes._MDNS_PORT)
            '''
            elif port == queryTypes._DNS_PORT:
                self.zeroconf.handle_query(msg, addr, port)
                self.zeroconf.handle_query(msg, queryTypes._MDNS_ADDR, queryTypes._MDNS_PORT)
            '''
        else:
            self.zeroconf.handle_response(msg)
