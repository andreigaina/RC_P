import socket

from ServiceTypes_find import ZeroconfServiceTypes
from serviceInfo import ServiceInfo
from zeroconf import Zeroconf

desc = {'path': '/~paulsm/'}

if __name__ == '__main__':

    info = ServiceInfo("_http._tcp.local.",
                   "Melinte._http._tcp.local.",
                   address=socket.inet_aton("10.0.1.2"), port=80, weight=0, priority=0,
                   properties=desc, server="ash-2.local.")

    zeroconf = Zeroconf()
    print("Registration of a service...")
    zeroconf.register_service(info)
    service_types = ZeroconfServiceTypes.find(interfaces=['0.0.0.0'], timeout=0.5)
    print(service_types)
    try:
       input("Waiting (press Enter to exit)...")
    finally:
        print("Unregistering...")
        zeroconf.unregister_service(info)
        zeroconf.close()
