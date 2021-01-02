import select
import threading
from queryTypes import *
import queryTypes


class Engine(threading.Thread):
    def __init__(self, zeroconf):
        super().__init__()
        self.daemon = True
        self.zeroconf = zeroconf
        self.readers = {}
        self.timeout = 5
        self.condition = threading.Condition()
        self.start()

    def add_reader(self, reader, socket_):
        with self.condition:
            self.readers[socket_] = reader
            self.condition.notify()

    def get_readers(self):
        with self.condition:
            result = self.readers.keys()
            # self.condition.notify()
        return result

    def delete_reader(self, socket_):
        with self.condition:
            del self.readers[socket_]
            self.condition.notify()

    def run(self):
        while not queryTypes._GLOBAL_DONE:
            result = self.get_readers()
            if len(result) == 0:

                with self.condition:
                    self.condition.wait(self.timeout)
            else:
                try:
                    rr, wr, er = select.select(result, [], [], self.timeout)
                    for socket_ in rr:
                        try:
                            self.readers[socket_].handle_read(socket_)
                        except Exception as e:
                            log.exception('Unknown error:%r', e)
                except Exception as e:
                    log.exception('Unknown error:%r', e)

    def notify(self):
        with self.condition:
            self.condition.notify()
