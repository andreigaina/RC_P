from zeroconf import *


if __name__ == '__main__':
    service_types = ZeroconfServiceTypes.find(timeout=0.5)
    print(service_types)

