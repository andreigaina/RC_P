from zeroconf import Zeroconf
from pieces import *


class MyListener(object):

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))
        print('\n')

    def add_service(self, zeroconf, type, name):
        print("Service %s added" % (name,))
        print("  Type is %s" % (type,))
        info = zeroconf.get_service_info(type, name)
        # print(info)
        if info:
            print("  Address is %s:%d" % (socket.inet_ntoa(info.address),
                                          info.port))
            print("  Weight is %d, Priority is %d" % (info.weight,
                                                      info.priority))
            print("  Server is", info.server)
            if info.properties:
                print("  Properties are")
                for key, value in info.properties.items():
                    print("    %s: %s" % (key, value))
        else:
            print("  No info")
        print('\n')


if __name__ == '__main__':

    zeroconf = Zeroconf()
    print("Browsing services...")
    listener = MyListener()
    # browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    listener1 = MyListener()
    browser2 = ServiceBrowser(zeroconf, "_xxxx._udp.local.", listener1)
    try:
        input("Waiting (press Enter to exit)...\n\n")
    finally:
        zeroconf.close()
