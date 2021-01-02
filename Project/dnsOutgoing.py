
from six import int2byte
import queryTypes
import struct


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
            self.write_short(record.class_ | queryTypes._CLASS_UNIQUE)
        else:
            self.write_short(record.class_)
        if now == 0:
            self.write_int(record.ttl)
        else:
            self.write_int(record.get_remaining_TTL(now))
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
