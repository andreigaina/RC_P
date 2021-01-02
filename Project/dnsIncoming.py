from six import indexbytes
from queryTypes import *
import queryTypes


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
        return (self.flags & queryTypes._FLAGS_QR_MASK) == queryTypes._FLAGS_QR_QUERY

    def is_response(self):
        """Returneaza true daca este de tip response"""
        return (self.flags & queryTypes._FLAGS_QR_MASK) == queryTypes._FLAGS_QR_RESPONSE

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
            if type_ == queryTypes._TYPE_A:
                record = DNSAddress(domain, type_, class_, ttl, self.read_string(4))
            elif type_ == queryTypes._TYPE_CNAME or type_ == queryTypes._TYPE_PTR:
                record = DNSPointer(domain, type_, class_, ttl, self.read_domain_name())
            elif type_ == queryTypes._TYPE_TXT:
                record = DNSText(domain, type_, class_, ttl, self.read_string(length))
            elif type_ == queryTypes._TYPE_SRV:
                record = DNSService(domain, type_, class_, ttl, self.read_unsigned_short()
                                    , self.read_unsigned_short(), self.read_unsigned_short(), self.read_domain_name())
            elif type_ == queryTypes._TYPE_AAAA:
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
