from zeroconf import *
from typing import Union
from serviceBrowser import *


class ZeroconfServiceTypes:
    def __init__(self) -> None:
        self.found_services = set()

    def add_service(self, zc, type_, name):
        self.found_services.add(name)

    @classmethod
    def find(
            cls,
            zc=None,
            timeout: Union[int, float] = 5,
            interfaces=InterfaceChoice.Default,
            ip_version=None):
        if zc is None:
            local_zc = Zeroconf(interfaces=interfaces)
        else:
            local_zc = zc
        listener = cls()
        browser = ServiceBrowser(local_zc, '_services._dns-sd._udp.local.', listener=listener)
        # wait for responses
        time.sleep(timeout)
        #close
        if zc is None:
            local_zc.close()
        else:
            browser.cancel()

        return tuple(sorted(listener.found_services))


if __name__ == '__main__':
    service_types = ZeroconfServiceTypes.find(timeout=0.5)
    print(service_types)
