import abc
import logging
from six import *

from functions import *

_MDNS_ADDR = '224.0.0.251'
_MDNS_ADDR6 = 'ff02::fb'

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
_FLAGS_QR_RESPONSE = 0x0000
_FLAGS_QR_MASK = 0x8000

_FLAGS_AA = 0x0400  # authorative answer

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

    def answeredBy(self, record) -> bool:
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

    def get_expiration_time(self):
        """Returneaza momentul la care aceasta inregistrare va expira"""
        return self.moment + self.ttl * 1000  # milliseconds

    def get_remaining_TTL(self, now):
        """Returneaza TTL-ul ramas"""
        return max(0, (self.get_expiration_time() - now) / 1000)  # seconds

    def is_expired(self, now) -> bool:
        """Returneaza true daca a expirat acest record"""
        return self.get_expiration_time() <= now

    def reset_TTL(self, other):
        """Resetam valoarea TTL-ului si a momentului crearii cu o alta valoarea a unui record mai recent"""
        self.moment = other.moment
        self.ttl = self.moment

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
        out_.write_short(self.server)

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


class DNSOutgoing:
    """Pachet de iesire(QUERY)"""

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
        """Punem o intrebare"""
        self.questions.append(record)

    def add_answer_at_time(self, record, now):
        """Se pune in pachet un raspuns daca nu expira pentru o anumita perioada de timp"""
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self.answers.append((record, now))

    def add_answer(self, msg, record):
        """Se pune un raspuns in pachet"""
        if not record.suppressed(msg):
            self.add_answer_at_time(record, 0)

    def add_authoritative_answer(self, record):
        """Se pune un  raspuns autoritar """
        self.authorities.append(record)

    def add_additional_answer(self, record):
        """Se pune un raspuns aditional """
        self.additionals.append(record)

    def pack(self, format_, value):
        """Adaug un camp in pachet"""
        self.data.append(struct.pack(format_, value))
        self.size += struct.calcsize(format_)

    def write_byte(self, value):
        """Scriu un byte in pachet(BIG ENDIAN)"""
        self.pack(b'!c', int2byte(value))  # char

    def insert_short(self, index, value):
        """Scriu un unsigned short int la o anumita pozitie in pachet(BIG_ENDIAN)"""
        self.data.insert(index, struct.pack(b'!H', value))  # unsigned short
        self.size += 2

    def write_short(self, value):
        """Scriu un unsigned short int in pachet(BIG_ENDIAN)"""
        self.pack(b'!H', value)

    def write_int(self, value):
        """Scriu un unsigned int in pachet(BIG_ENDIAN)"""
        self.pack(b'!I', int(value))

    def write_string(self, value):
        """Scriu un string in pachet"""
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def write_utf8(self, string):
        """Scriu un string si lungimea lui in pachet(BIG_ENDIAN)"""
        utf_string = string.encode('utf-8')
        length = len(utf_string)
        if length > 64:
            raise Exception("String too long!")
        self.write_byte(length)
        self.write_string(utf_string)

    def write_domain_name(self, name):
        """Scriu numele domeniului in pachet"""
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
        """Scriu o intrebare in pachet"""
        self.write_domain_name(question.name)
        self.write_short(question.type_)
        self.write_short(question.class_)

    def write_record(self, record, now):
        """Scriu un record(raspunst, raspuns autoritar, raspuns aditional) in pachet"""
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
        """Impachetam informatiile"""
        # SCHEMA: ID->FLAGS->NR_QUESTIONS->NR_ANSWERS->NR_AUTHORITIES->
        # NR_ADDITIONALS->QUESTIONS->ANSWERS->AUTHORITIES->ADDTIONALS->0
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

    def __repr__(self) -> str:
        """Reprezentarea de tip string"""
        return '<DNSOutgoing:{%s}' % ''.join(
            [
                'multicast=%s, ' % self.id,
                'flags=%s, ' % self.flags,
                'questions=%s, ' % self.questions,
                'answers=%s, ' % self.answers,
                'authorities=%s, ' % self.authorities,
                'additionals=%s, ' % self.additionals
            ]
        )


class DNSIncoming:
    """"Pachet de intrare(RESPONSE)"""

    def __init__(self, data):
        self.offset = 0
        self.data = data
        self.questions = []
        self.answers = []
        self.id = 0
        self.flags = 0
        self.nr_questions = 0
        self.nr_answers = 0
        self.nr_authorities = 0
        self.nr_additionals = 0

        self.read_header()
        self.read_questions()
        self.read_other_data()

    def unpack(self, format_):
        """Extragem o anumita informatie din pachet"""
        length = struct.calcsize(format_)
        info = struct.unpack(format_, self.data[self.offset:self.offset + length])
        self.offset += length
        return info

    def read_header(self):
        """Citim header-ul pentru a afla informatiile necesare continuarii despachetarii"""
        (
            self.id,
            self.flags,
            self.nr_questions,
            self.nr_answers,
            self.nr_authorities,
            self.nr_additionals,
        ) = self.unpack(b'!6H')

    def read_int(self):
        """Citim un unsigned int din pachet"""
        return self.unpack(b'!I')[0]

    def read_unsigned_short(self):
        """Citim un unsigned short din pachet"""
        return self.unpack(b'!H')[0]

    def read_string(self, length):
        """Citim un string de o anumita lungime din pachet"""
        info = self.data[self.offset:self.offset + length]
        self.offset += length
        return info

    def read_character_string(self):
        """Citim un caracter din pachet"""
        length = indexbytes(self.data, self.offset)
        self.offset += 1
        return self.read_string(length)

    def is_query(self):
        """Returneaza true daca este de tip query"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self):
        """Returneaza true daca este de tip response"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

    def read_utf8(self, offset, length):
        """Citim un string de o anumita lungime si de la un anumit offset din pachet"""
        return str(self.data[offset: offset + length], encoding='utf-8', errors='replace')

    def read_domain_name(self):
        """Citim numele domeniului"""
        result = ''
        offset = self.offset
        next_off = -1
        first = offset
        while True:
            length = indexbytes(self.data, offset)
            offset += 1
            if length == 0:
                break
            t = length & 0xC0
            if t == 0x00:
                result = ''.join((result, self.read_utf8(offset, length) + '.'))
                offset += length
            elif t == 0xC0:
                if next_off < 0:
                    next_off = offset + 1
                offset = ((length & 0x3F) << 8) | indexbytes(self.data, offset)  # Turn back to the domain name
                if offset >= first:
                    raise Exception("Bad domain name (circular) at %s!" % offset)
                first = offset
            else:
                raise Exception("Bad domain name at %s" % offset)
        if next_off >= 0:
            self.offset = next_off
        else:
            self.offset = offset
        return result

    def read_questions(self):
        """Citim intrebarile din pachet"""
        for j in range(self.nr_questions):
            name = self.read_domain_name()
            type_, class_ = self.unpack(b'!HH')
            question = DNSQuestion(name, type_, class_)
            self.questions.append(question)

    def read_other_data(self):
        """Citim alte date din pachet(raspunsuri)"""
        nr = self.nr_answers + self.nr_authorities + self.nr_additionals
        for j in range(nr):
            domain = self.read_domain_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH')
            record = None
            if type_ == _TYPE_A:
                record = DNSAddress(domain, type_, class_, ttl, self.read_string(4))
            elif type_ == _TYPE_CNAME or type_ == _TYPE_PTR:
                record = DNSPointer(domain, type_, class_, ttl, self.read_domain_name())
            elif type_ == _TYPE_TXT:
                record = DNSText(domain, type_, class_, ttl, self.read_string(length))
            elif type_ == _TYPE_SRV:
                record = DNSService(domain, type_, class_, ttl, self.read_unsigned_short()
                                    , self.read_unsigned_short(), self.read_unsigned_short(), self.read_domain_name())
            elif type_ == _TYPE_AAAA:
                record = DNSAddress(domain, type_, class_, ttl, self.read_string(16))  # ipV6
            else:
                self.offset += length
            if record is not None:
                self.answers.append(record)

    def __repr__(self) -> str:
        """Reprezentarea de tip string a pachetului"""
        return '<DNSIncoming:{%s}' % ''.join(
            [
                'id=%s, ' % self.id,
                'flags=%s, ' % self.flags,
                'nr_q=%s, ' % self.nr_questions,
                'nr_ans=%s, ' % self.nr_answers,
                'nr_auth=%s, ' % self.nr_authorities,
                'nr_add=%s, ' % self.nr_additionals,
                'questions=%s, ' % self.questions,
                'answers=%s, ' % self.answers
            ]
        )


class ServiceInfo:
    def __init__(self, type_, name: str, address=None, port=None, weight=0, priority=0, properties=None, server=None):
        if not name.endswith(type_):
            raise Exception("Bad type name!")
        self.type_ = type_
        self.name = name
        self.address = address
        self.port = port
        self.weight = weight
        self.priority = priority
        if server:
            self.server = server
        else:
            self.server = name
        self._set_properties(properties)

    def _set_properties(self, properties):
        if isinstance(properties, dict):
            self._properties = properties
            list_ = []
            result = b''
            for key in properties:
                value = properties[key]
                if isinstance(key, text_type):
                    key = key.encode('utf-8')
                if value is not None:
                    if not isinstance(value, bytes):
                        value = str(value).encode('utf-8')
                list_.append(b'='.join((key, value)))
            for item in list_:
                result = b''.join((result, int2byte(len(item)), item))
            self.text = result
        else:
            self.text = properties

    def _set_text(self, text):
        self.text = text
        result = {}
        end = len(text)
        index = 0
        values = []
        while index < end:
            length = indexbytes(text, index)
            values.append(text[index:index+length])
            index += length+1  # lungimea inregistrarii + octetul care retinea lungimea inregistrarii

        for v in values:
            try:
                key, value = v.split(b'=', 1)
            except Exception as e:
                log.exception('Unknown error, possibly: %r', e)
                key = v
                value = False
            if key and result.get(key) is None:
                result[key] = value
        self._properties = result

    def get_name(self):
        if self.type_ is not None and self.name.endswith("." + self.type_):
            return self.name[:len(self.name)-len(self.type_)-1]
        return self.name

    def update_record(self, zerocfg, now, record):
        if record is not None and not record.is_expired(now):
            if record.type_ == _TYPE_A:
                if record.name == self.server:
                    self.address = record.address
                elif record.type == _TYPE_SRV:
                    if record.type == _TYPE_SRV:
                        self.server = record.server
                        self.port = record.port
                        self.weight = record.weight
                        self.priority = record.priority
                        #--------------
                elif record.type == _TYPE_TXT:
                    if record.name == self.name:
                        self._set_text(record.text)


class ServiceBrowser:
    pass


def send(out_, addr=_MDNS_ADDR, port=_MDNS_PORT):
    packet = out_.packet()
    socket = new_socket()
    bytes_sent = socket.sendto(packet, (addr, port))
    # print(len(packet))
    if bytes_sent != len(packet):
        raise Exception(
            'Sent %d out of %d bytes!' % (bytes_sent, len(packet)))


if __name__ == '__main__':

    i = 0
    out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)

    out.add_question(DNSQuestion("_http._tcp.local.", _TYPE_PTR, _CLASS_IN))
    # out.add_authoritative_answer(
    #     DNSPointer("_http._tcp.local.", _TYPE_PTR, _CLASS_IN, _DNS_TTL, "Paul's Test Web Site._http._tcp.local."))
    while i < 3:
        print(out.packet())
        send(out)
        i += 1
