from functools import reduce
from queryTypes import *


class DNSCache:
    def __init__(self):
        self.cache = {}

    def add(self, entry):
        self.cache.setdefault(entry.key, []).append(entry)

    def remove(self, entry):
        try:
            list__ = self.cache[entry.key]
            list__.remove(entry)
            if not list__:
                del self.cache[entry.key]
        except (KeyError, ValueError):
            pass

    def get(self, entry):
        try:
            list__ = self.cache[entry.key]
            '''
            for cached_entry in reversed(list__):
                if entry.__eq__(cached_entry):
                    return cached_entry
            return None
            '''
            return list__[list__.index(entry)]
        except (KeyError, ValueError):
            return None

    def get_by_details(self, name, type_, class_):
        entry = DNSEntry(name, type_, class_)
        return self.get(entry)

    def entries(self):
        if not self.cache:
            return []
        else:
            return reduce(lambda x, y: x + y, self.cache.values())

    def entries_with_name(self, name):
        try:
            return self.cache[name]

        except KeyError:
            return []
