import threading
from queryTypes import *
import queryTypes


class Reaper(threading.Thread):
    def __init__(self, zeroconf):
        super().__init__()
        self.daemon = True
        self.zeroconf = zeroconf
        self.start()

    def run(self):
        while True:
            self.zeroconf.wait(10 * 1000)
            if queryTypes._GLOBAL_DONE:
                return
            now = current_time_millis()
            for record in self.zeroconf.cache.entries():
                if record.is_expired(now):
                    self.zeroconf.update_record(now, record)
                    self.zeroconf.cache.remove(record)
