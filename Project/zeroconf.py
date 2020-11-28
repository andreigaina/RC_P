import abc
import logging

from functions import *

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

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

if log.level == logging.NOTSET:
    log.setLevel(logging.WARN)

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
                self.type_ == other.type_ and
                self.class_ == other.class_)

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    """****************Types and classes accessor***************"""

    @staticmethod
    def get_class(class_) -> str:
        return _CLASSES.get(class_, "NotRecognisedClass(%s)" % class_)

    @staticmethod
    def get_type(type_) -> str:
        return _TYPES.get(type_, "NotRecognisedType(%s)" % type_)

    def to_string(self, other_info=None, whatIsThis=None) -> str:
        result = "%s[%s, %s, " % (whatIsThis, self.get_type(self.type_), self.get_class(self.class_))
        result += self.name
        if other_info is not None:
            result += ", %s]" % other_info
        else:
            result += "]"
        return result


class DNSQuestion(DNSEntry):
    """*****************Question entry******************"""

    def __init__(self, name, type_, class_):
        super().__init__(name, type_, class_)

    def answeredBy(self, record) -> bool:
        return (self.class_ == record.class_ and
                (self.type_ == record.type_ or
                 self.type_ == _TYPE_ANY) and
                self.name == record.name)

    def __repr__(self) -> str:
        return super().to_string(whatIsThis="question")


class DNSRecord(DNSEntry):
    """**************Record with TIME TO LIVE(TTL)***************** """
    __metaclass__ = abc.ABCMeta

    def __init__(self, name, type_, class_, ttl):
        super().__init__(name, type_, class_)
        self.ttl = ttl
        self.moment = current_time_millis()

    def __eq__(self, other) -> bool:
        return isinstance(other, DNSRecord) and DNSEntry.__eq__(self, other)

    def suppressed_by_answer(self, other) -> bool:
        return self == other and other > (self.ttl / 2)

    def suppressed(self, msg) -> bool:
        for record in msg.answers:
            if self.suppressed_by_answer(record):
                return True
        return False

    def get_expiration_time(self):
        return self.moment + self.ttl * 1000  # milliseconds

    def get_remaining_TTL(self, now):
        return max(0, (self.get_expiration_time() - now) / 1000)  # seconds

    def is_expired(self, now) -> bool:
        return self.get_expiration_time() <= now

    def reset_TTL(self, other):
        self.moment = other.moment
        self.ttl = self.moment

    @abc.abstractmethod
    def write(self, out):
        pass

    def to_string(self, other_info=None, whatIsThis=None) -> str:
        info = "%s/%s" % (self.ttl,
                          self.get_remaining_TTL(current_time_millis()))
        if other_info is not None:
            info += ",%s" % other_info
        return super().to_string(whatIsThis="record", other_info=info)


class DNSAddress(DNSRecord):
    def __init__(self, name, type_, class_, ttl, address):
        super().__init__(name, type_, class_, ttl)
        self.address = address

    def write(self, out):
        out.write_string(self.address)

    def __eq__(self, other):
        return isinstance(other, DNSAddress) and self.address == other.address

    def __repr__(self):
        try:
            return socket.inet_aton(self.address) #32 bit packed binary format
        except Exception as e:
            log.exception('Unknow error: %r', e)
            return self.address


class DNSPointer(DNSRecord):
    def write(self, out):
        pass


class DNSText(DNSRecord):
    def write(self, out) -> str:
        pass


class DNSOutgoing:
    pass


class DNSIncoming:
    pass


class ServiceBrowser:
    pass


if __name__ == '__main__':
    pass
