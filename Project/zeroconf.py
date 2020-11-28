import abc
import logging
from six import *

from functions import *

_MDNS_ADDR = '224.0.0.251'
_MDNS_PORT = 5353
_DNS_TTL = 60 * 60  # 1h
_CLASS_IN = 1
_CLASS_ANY = 255
_CLASS_MASK = 0x7FFF
_CLASS_UNIQUE = 0X8000

_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_ANY = 255

_FLAGS_QR_QUERY = 0x0000  # query

_FLAGS_AA = 0x0400  # authorative answer

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
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0

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
        if self.unique:
            result += "-unique,"
        else:
            result += ","
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
            return self.to_string(socket.inet_aton(self.address))  # 32 bit packed binary format
        except Exception as e:
            log.exception('Unknow error: %r', e)
            return self.to_string(str(self.address))


class DNSPointer(DNSRecord):
    def __init__(self, name, type_, class_, ttl, alias):
        super().__init__(name, type_, class_, ttl)
        self.alias = alias

    def write(self, out):
        out.write_domain_name(self.alias)

    def __eq__(self, other):
        return isinstance(other, DNSPointer) and self.alias == other.alias

    def __repr__(self):
        return self.to_string(self.alias)


class DNSText(DNSRecord):
    def __init__(self, name, type_, class_, ttl, text):
        assert isinstance(text, (bytes, type(None)))
        super().__init__(name, type_, class_, ttl)
        self.text = text

    def write(self, out):
        out.write_string(self.text)

    def __eq__(self, other):
        return isinstance(other, DNSText) and self.text == other.text

    def __repr__(self):
        return self.to_string(self.text)


class DNSService(DNSRecord):
    def __init__(self, name, type_, class_, ttl, priority, weight, port, server):
        super().__init__(name, type_, class_, ttl)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server

    def write(self, out):
        out.write_short(self.priority)
        out.write_short(self.weight)
        out.write_short(self.port)
        out.write_short(self.server)

    def __eq__(self, other):
        return (isinstance(other, DNSService) and
                self.priority == other.priority and
                self.weight == other.weight and
                self.port == other.port and
                self.server == other.server)

    def __repr__(self):
        return self.to_string("%s:%s" % (self.server, self.port))


class DNSOutgoing:
    def __init__(self, flags, multicast=True):
        self.finished = False
        self.id = 0
        self.multicast = multicast
        self.flags = flags
        self.names = {}
        self.data = []
        self.size = 12

        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def add_question(self, record):
        self.questions.append(record)

    def add_answer_at_time(self, record, now):
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self.answers.append((record, now))

    def add_answer(self, msg, record):
        if not record.suppressed(msg):
            self.add_answer_at_time(record, 0)

    def add_authorative_answer(self, record):
        self.authorities.append(record)

    def add_additional_answer(self, record):
        self.additionals.append(record)

    def pack(self, format, value):
        self.data.append(struct.pack(format, value))
        self.size += struct.calcsize(format)

    def write_byte(self, value):
        self.pack(b'!c', int2byte(value))  # char

    def insert_short(self, index, value):
        self.data.insert(index, struct.pack(b'!H', value))  # unsigned short
        self.size += 2

    def write_short(self, value):
        self.pack(b'!H', value)

    def write_int(self, value):
        self.pack(b'!I', int(value))

    def write_string(self, value):
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def write_utf8(self, string):
        utf_string = string.encode('utf-8')
        length = len(utf_string)
        if length > 64:
            raise Exception("String too long!")
        self.write_byte(length)
        self.write_string(utf_string)

    def write_domain_name(self, name):
        if name in self.names:
            index = self.names[name]
            self.write_byte((index >> 8) | 0xC0)
            self.write_byte(index & 0xFF)
        else:
            self.names[name] = self.size
            parts = name.split('.')
            if parts[-1] == '':
                parts = parts[:-1]
            for part in parts:
                self.write_utf8(part)
            self.write_byte(0)

    def write_question(self, question):
        self.write_domain_name(question.name)
        self.write_short(question.type_)
        self.write_short(question.class_)

    def write_record(self, record, now):
        self.write_domain_name(record.name)
        self.write_short(record.type_)
        if record.unique and self.multicast:
            self.write_short(record.class_ | _CLASS_UNIQUE)
        else:
            self.write_short(record.class_)
        if now == 0:
            self.write_int(record.ttl)
        else:
            self.write_int(record.get_remaining_ttl(now))
        index = len(self.data)
        self.size += 2
        record.write(self)
        self.size -= 2
        length = len(b''.join(self.data[index:]))
        self.insert_short(index, length)

    def packet(self):
        if not self.finished:
            self.finished = True
            for question in self.questions:
                self.write_question(question)
            for answer, time_ in self.answers:
                self.write_record(answer, time_)
            for authority in self.authorities:
                self.write_record(authority, 0)
            for additional in self.additionals:
                self.write_record(additional, 0)

            self.insert_short(0, len(self.additionals))
            self.insert_short(0, len(self.authorities))
            self.insert_short(0, len(self.answers))
            self.insert_short(0, len(self.questions))
            self.insert_short(0, self.flags)
            if self.multicast:
                self.insert_short(0, 0)
            else:
                self.insert_short(0, self.id)
        return b''.join(self.data)


class DNSIncoming:
    pass


class ServiceBrowser:
    pass


def send(out, addr=_MDNS_ADDR, port=_MDNS_PORT):
    packet = out.packet()
    socket = new_socket()
    bytes_sent = socket.sendto(packet, (addr, port))
    print(len(packet))
    if bytes_sent != len(packet):
        raise Exception(
            'Sent %d out of %d bytes!' % (bytes_sent, len(packet)))


if __name__ == '__main__':
    i = 0
    while i < 3:
        out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
        out.add_question(DNSQuestion("_http._tcp.local.", _TYPE_PTR, _CLASS_IN))
        out.add_authorative_answer(
            DNSPointer("_http._tcp.local.", _TYPE_PTR, _CLASS_IN, _DNS_TTL, "Paul's Test Web Site._http._tcp.local."))
        print(out.packet())
        send(out)
        i += 3
