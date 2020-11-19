import socket

_MDNS_ADDR = '224.0.0.251'
_MDNS_PORT = 5353

_CLASS_IN = 1
_CLASS_ANY = 255
_CLASS_MASK = 0x7FFF

_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_ANY = 255

# Mapping constants to names

_CLASSES = {_CLASS_IN: "in",
            _CLASS_ANY: "any"}
_TYPES = {_TYPE_A: "a",
          _TYPE_PTR: "ptr",
          _TYPE_TXT: "txt",
          _TYPE_AAAA: "4xa",
          _TYPE_SRV: "srv",
          _TYPE_ANY: "any"}


class DNSEntry:
    """*************** DNS Entry ****************"""

    def __init__(self, name, type_, class_):
        self.key = name.lower()
        self.name = name
        self.type_ = type_
        self.class_ = class_

    def __eq__(self, other) -> bool:
        return (isinstance(other, DNSEntry) and
                self.name == other.name and
                self.type == other.type and
                self.class_ == other.class_)

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    """****************Types and classes accessor***************"""

    def get_class(self, class_) -> str:
        return _CLASSES.get(class_, "NotRecognisedClass(%s)" % class_)

    def get_type(self, type_) -> str:
        return _TYPES.get(type_, "NotRecognisedType(%s)" % type_)

    def to_string(self, whatIsThis) -> str:
        result = "%s[%s, %s, " % (whatIsThis, self.get_type(self.type_), self.get_class(self.class_))
        result += self.name
        result += "]"
        return result


class DNSQuestion(DNSEntry):
    """*****************Question entry******************"""

    def __init__(self, name, type_, class_):
        DNSEntry.__init__(self, name, type_, class_)

    def answeredBy(self, record) -> bool:
        return (self.class_ == record.class_ and
                (self.type_ == record.type_ or
                 self.type_ == _TYPE_ANY) and
                self.name == record.name)

    def __repr__(self):
        return DNSEntry.to_string(self, whatIsThis="question")


class DNSRecord(DNSEntry):
    """**************Record with TIME TO LIVE(TTL)***************** """

    def __init__(self, name, type_, class_, ttl):
        DNSEntry.__init__(self, name, type_,class_ )
        self.ttl = ttl
        


class DNSAddress(DNSRecord):
    pass


class DNSPointer(DNSRecord):
    pass


class DNSText(DNSRecord):
    pass


class DNSOutgoing:
    pass


class DNSIncoming:
    pass


class ServiceBrowser:
    pass


def new_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # More than one process needs to bind to the same SOCK_DGRAM port =>
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Unrestricted in scope
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    # Enable loopback
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)


if __name__ == '__main__':
    pass
