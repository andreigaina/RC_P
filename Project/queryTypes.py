from dnsOutgoing import *
from functions import *
import abc
import logging

_GLOBAL_DONE = False
_MAX_MSG_ABSOLUTE = 8972
_CHECK_TIME = 175
_REGISTER_TIME = 225
_UNREGISTER_TIME = 125
_BROWSER_TIME = 500

_MDNS_ADDR = '224.0.0.251'
_MDNS_ADDR6 = 'ff02::fb'

_DNS_PORT = 53
_MDNS_PORT = 5353
_DNS_TTL = 60 * 60  # 1h
_CLASS_IN = 1
_CLASS_ANY = 255
_CLASS_MASK = 0x7FFF
_CLASS_UNIQUE = 0X8000

_TYPE_A = 1
_TYPE_CNAME = 5
_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_ANY = 255

_FLAGS_QR_QUERY = 0x0000  # query
_FLAGS_QR_RESPONSE = 0x8000
_FLAGS_QR_MASK = 0x8000

_FLAGS_AA = 0x0400  # authorative answer

_LISTENER_TIME = 200
# Mapping constants to names

_CLASSES = {_CLASS_IN: "in",
            _CLASS_ANY: "any"}
_TYPES = {_TYPE_A: "a",
          _TYPE_CNAME: "cname",
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
    """Clasa de baza DNSEntry"""

    def __init__(self, name, type_, class_):
        self.key = name.lower()
        self.name = name
        self.type_ = type_
        self.class_ = class_ & _CLASS_MASK
        """Raspunde un singur owner"""
        self.unique = (class_ & _CLASS_UNIQUE) != 0

    def __eq__(self, other) -> bool:
        """ Metoda ce verifica daca doua obiecte de tip DNSEntry au acelasi nume, tip si clasa"""
        return (isinstance(other, DNSEntry) and
                self.name == other.name and
                self.type_ == other.type_ and
                self.class_ == other.class_)

    def __ne__(self, other) -> bool:
        return not self.__eq__(other)

    @staticmethod
    def get_class(class_) -> str:
        """Returnam tipul clasei sau un mesaj de err"""
        return _CLASSES.get(class_, "NotRecognisedClass(%s)" % class_)

    @staticmethod
    def get_type(type_) -> str:
        """Returnam tipul inregistrarii sau un mesaj de err"""
        return _TYPES.get(type_, "NotRecognisedType(%s)" % type_)

    def to_string(self, other_info=None, whatIsThis=None) -> str:
        """Metoda ce returneaza un string cu informatiile despre DSNEntry"""
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
    """DNSQuestion"""

    def __init__(self, name, type_, class_):
        super().__init__(name, type_, class_)

    def answered_by(self, record) -> bool:
        """Se returneaza valoarea de adevar 1 daca raspunsul la o intrebare este dat de record"""
        return (self.class_ == record.class_ and
                (self.type_ == record.type_ or
                 self.type_ == _TYPE_ANY) and
                self.name == record.name)

    def __repr__(self) -> str:
        """Reprezentare de tip string"""
        return super().to_string(whatIsThis="question")


class DNSRecord(DNSEntry):
    """Record cu time to live(TTL)"""
    __metaclass__ = abc.ABCMeta

    def __init__(self, name, type_, class_, ttl):
        super().__init__(name, type_, class_)
        self.ttl = ttl
        self.moment = current_time_millis()

    def __eq__(self, other) -> bool:
        return isinstance(other, DNSRecord) and DNSEntry.__eq__(self, other)

    def suppressed_by_answer(self, other) -> bool:
        """Returneaza true daca o alta inregistrare are acelasi nume, acelasi tip, aceeasi clasa si TTL>self.ttl/2 """
        return self == other and other > (self.ttl / 2)

    def suppressed(self, msg) -> bool:
        """Returneaza true daca un raspuns din oricare mesaj poate fi indeajuns pentru informatiile mentinute in
        acest record """
        for record in msg.answers:
            if self.suppressed_by_answer(record):
                return True
        return False

    def get_expiration_time(self, percent):
        """Returneaza momentul la care aceasta inregistrare va expira"""
        return self.moment + (percent * self.ttl * 10)  # milliseconds

    def get_remaining_TTL(self, now):
        """Returneaza TTL-ul ramas"""
        return max(0, (self.get_expiration_time(100) - now) / 1000)  # seconds

    def is_expired(self, now) -> bool:
        """Returneaza true daca a expirat acest record"""
        return self.get_expiration_time(100) <= now

    def reset_TTL(self, other):
        """Resetam valoarea TTL-ului si a momentului crearii cu o alta valoarea a unui record mai recent"""
        self.moment = other.moment
        self.ttl = other.ttl

    @abc.abstractmethod
    def write(self, out_):
        pass

    def to_string(self, other_info=None, whatIsThis=None) -> str:
        """Reprezentarea de tip string la care putem adauga si alte informatii"""
        info = "%s/%s" % (self.ttl,
                          self.get_remaining_TTL(current_time_millis()))
        if other_info is not None:
            info += ",%s" % other_info
        return super().to_string(whatIsThis="record", other_info=info)


class DNSAddress(DNSRecord):
    """DNSRecord de tip A(address)"""

    def __init__(self, name, type_, class_, ttl, address):
        super().__init__(name, type_, class_, ttl)
        self.address = address

    def write(self, out_):
        """Metoda folosita la crearea pachetelor de iesire"""
        out_.write_string(self.address)

    def __eq__(self, other):
        """Testam egalitatea"""
        return isinstance(other, DNSAddress) and self.address == other.address

    def __repr__(self):
        """Reprezentare de tip string"""
        try:
            return self.to_string(socket.inet_aton(self.address))  # 32 bit packed binary format
        except Exception as e:
            log.exception('Unknown error: %r', e)
            return self.to_string(str(self.address))


class DNSPointer(DNSRecord):
    """DNSRecord de tip PTR(pointer)"""

    def __init__(self, name, type_, class_, ttl, alias):
        super().__init__(name, type_, class_, ttl)
        self.alias = alias

    def write(self, out_):
        """Metoda folosita la crearea pachetelor de iesire"""
        out_.write_domain_name(self.alias)

    def __eq__(self, other):
        """Testam egalitatea"""
        return isinstance(other, DNSPointer) and self.alias == other.alias

    def __repr__(self):
        """Reprezentare de tip string"""
        return self.to_string(self.alias)


class DNSText(DNSRecord):
    """DNSRecord de tip TXT(TEXT)"""

    def __init__(self, name, type_, class_, ttl, text):
        assert isinstance(text, (bytes, type(None)))
        super().__init__(name, type_, class_, ttl)
        self.text = text

    def write(self, out_):
        """Metoda folosita la crearea pachetelor de iesire"""
        out_.write_string(self.text)

    def __eq__(self, other):
        """Testam egalitatea"""
        return isinstance(other, DNSText) and self.text == other.text

    def __repr__(self):
        """Reprezentare de tip string"""
        return self.to_string(self.text)


class DNSService(DNSRecord):
    """DNSRecord de tip SRV(SERVICE)"""

    def __init__(self, name, type_, class_, ttl, priority, weight, port, server):
        super().__init__(name, type_, class_, ttl)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server

    def write(self, out_):
        """Metoda folosita la crearea pachetelor de iesire"""
        out_.write_short(self.priority)
        out_.write_short(self.weight)
        out_.write_short(self.port)
        out_.write_domain_name(self.server)

    def __eq__(self, other):
        """Testam egalitatea"""
        return (isinstance(other, DNSService) and
                self.priority == other.priority and
                self.weight == other.weight and
                self.port == other.port and
                self.server == other.server)

    def __repr__(self):
        """Reprezentare de tip string"""
        return self.to_string("%s:%s" % (self.server, self.port))


if __name__ == '__main__':

    i = 0
    out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)

    out.add_question(DNSQuestion("_http._tcp.local.", _TYPE_PTR, _CLASS_IN))
    # out.add_authoritative_answer(
    #     DNSPointer("_http._tcp.local.", _TYPE_PTR, _CLASS_IN, _DNS_TTL, "Andrei's Test Web Site._http._tcp.local."))
    while i < 3:
        print(out.packet())
        send(out)
        i += 1
