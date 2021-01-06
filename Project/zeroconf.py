import ipaddress
from typing import cast

from listener import *
from dnscache import *
from reaper import *
from wrapper import *
from serviceInfo import *
from serviceBrowser import *
from queryTypes import *


def can_send_to(sock: socket.socket, address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return cast(bool, addr.version == 6 if sock.family == socket.AF_INET6 else addr.version == 4)


class Zeroconf:
    def __init__(self, interfaces=InterfaceChoice.All):
        queryTypes._GLOBAL_DONE = False
        self._listen_socket = new_socket()
        interfaces = normalize_interface_choice(interfaces, socket.AF_INET)

        self._respond_sockets = []

        for i in interfaces:
            self._listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                           socket.inet_aton(queryTypes._MDNS_ADDR) + socket.inet_aton(i))

            respond_socket = new_socket()
            respond_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(i))
            self._respond_sockets.append(respond_socket)

        self.listeners = []
        self.browsers = []
        self.services = {}
        self.servicetypes = {}
        self.condition = threading.Condition()

        self.cache = DNSCache()
        self.engine = Engine(self)
        self.listener = Listener(self)
        self.engine.add_reader(self.listener, self._listen_socket)
        self.reaper = Reaper(self)

    def wait(self, timeout):
        with self.condition:
            self.condition.wait(timeout / 1000)

    def notify_all(self):
        with self.condition:
            self.condition.notify_all()

    def get_service_info(self, type_, name, timeout=3000):
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info
        return None

    def remove_service_listener(self, listener):
        for browser in self.browsers:
            if browser.listener == listener:
                browser.cancel()
                del browser

    def add_service_listener(self, type_, listener):
        self.remove_service_listener(listener)
        self.browsers.append(ServiceBrowser(self, type_, listener))

    def send(self, out_, addr=queryTypes._MDNS_ADDR, port=queryTypes._MDNS_PORT):
        packet = out_.packet()
        for socket_ in self._respond_sockets:
            if queryTypes._GLOBAL_DONE:
                return
            if addr is None:
                real_addr = queryTypes._MDNS_ADDR
            elif not can_send_to(socket_, addr):
                continue
            else:
                real_addr = addr
            bytes_sent = socket_.sendto(packet, 0, (real_addr, port))
            # print(len(packet))
            if bytes_sent != len(packet):
                raise Exception(
                    'Sent %d out of %d bytes!' % (bytes_sent, len(packet)))

    def check_service(self, info, allow_name_change=True):
        next_instance_number = 2
        instance_name = info.name[:-len(info.type_) - 1]
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            for record in self.cache.entries_with_name(info.type_):
                if record.type_ == queryTypes._TYPE_PTR and not record.is_expired(now) and record.alias == info.name:
                    if not allow_name_change:
                        raise Exception("NonUniqueNameException")
                    info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type_)
                    next_instance_number += 1
                    self.check_service(info)
                    return

            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            out = DNSOutgoing(queryTypes._FLAGS_QR_QUERY | queryTypes._FLAGS_AA)
            self.debug = out
            out.add_question(DNSQuestion(info.type_, queryTypes._TYPE_PTR, queryTypes._CLASS_IN))
            out.add_authoritative_answer(DNSPointer(info.type_, queryTypes._TYPE_PTR, queryTypes._CLASS_IN,
                                                    queryTypes._DNS_TTL, info.name))
            self.send(out)
            i += 1
            next_time += queryTypes._CHECK_TIME

    def register_service(self, info, ttl=queryTypes._DNS_TTL):
        self.check_service(info)
        self.services[info.name.lower()] = info
        if info.type_ in self.servicetypes:
            self.servicetypes[info.type_] += 1
        else:
            self.servicetypes[info.type_] = 1
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA)
            out.add_answer_at_time(DNSPointer(info.type_, queryTypes._TYPE_PTR, queryTypes._CLASS_IN, ttl, info.name), 0)
            out.add_answer_at_time(DNSService(info.name, queryTypes._TYPE_SRV, queryTypes._CLASS_IN, ttl, info.priority,
                                              info.weight, info.port, info.server), 0)
            out.add_answer_at_time(DNSText(info.name, queryTypes._TYPE_TXT, queryTypes._CLASS_IN, ttl, info.text), 0)
            if info.address:
                out.add_answer_at_time(DNSAddress(info.server, queryTypes._TYPE_A, queryTypes._CLASS_IN, ttl, info.address), 0)

            self.send(out)
            i += 1
            next_time += queryTypes._REGISTER_TIME

    def unregister_service(self, info):
        try:
            del self.services[info.name.lower()]
            if self.servicetypes[info.type_] > 1:
                self.servicetypes[info.type_] -= 1
            else:
                del self.servicetypes[info.type_]
        except Exception as e:
            log.exception('Unknown error:%r', e)
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA)
            out.add_answer_at_time(DNSPointer(info.type_, queryTypes._TYPE_PTR, queryTypes._CLASS_IN, 0, info.name), 0)
            out.add_answer_at_time(DNSService(info.name, queryTypes._TYPE_SRV, queryTypes._CLASS_IN, 0, info.priority,
                                              info.weight, info.port, info.server), 0)
            out.add_answer_at_time(DNSText(info.name, queryTypes._TYPE_TXT, queryTypes._CLASS_IN, 0, info.text), 0)
            if info.address:
                out.add_answer_at_time(DNSAddress(info.server, queryTypes._TYPE_A, queryTypes._CLASS_IN, 0, info.address), 0)
            self.send(out)
            i += 1
            next_time += queryTypes._UNREGISTER_TIME

    def unregister_all_services(self):
        if len(self.services) > 0:
            now = current_time_millis()
            next_time = now
            i = 0
            while i < 3:
                if now < next_time:
                    self.wait(next_time - now)
                    now = current_time_millis()
                    continue
                out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA)
                for info in self.services.values():
                    out.add_answer_at_time(DNSPointer(info.type_, queryTypes._TYPE_PTR, queryTypes._CLASS_IN, 0, info.name), 0)
                    out.add_answer_at_time(DNSService(info.name, queryTypes._TYPE_SRV, queryTypes._CLASS_IN, 0, info.priority,
                                                      info.weight, info.port, info.server), 0)
                    out.add_answer_at_time(DNSText(info.name, queryTypes._TYPE_TXT, queryTypes._CLASS_IN, 0, info.text), 0)
                    if info.address:
                        out.add_answer_at_time(
                            DNSAddress(info.server, queryTypes._TYPE_A, queryTypes._CLASS_IN, 0, info.address), 0)
                self.send(out)
                i += 1
                next_time += queryTypes._UNREGISTER_TIME

    def update_record(self, now, record):
        for listener in self.listeners:
            listener.update_record(self, now, record)
        self.notify_all()

    def add_listener(self, listener, question):
        now = current_time_millis()
        self.listeners.append(listener)
        if question is not None:
            for record in self.cache.entries_with_name(question.name):
                if question.answered_by(record) and not record.is_expired(now):
                    listener.update_record(self, now, record)
        self.notify_all()

    def remove_listener(self, listener):
        try:
            self.listeners.remove(listener)
            self.notify_all()
        except Exception as e:
            log.exception('Unknown error:%r', e)

    def handle_response(self, msg):
        now = current_time_millis()
        for record in msg.answers:
            expired = record.is_expired(now)
            if record in self.cache.entries():
                if expired:
                    self.cache.remove(record)
                else:
                    entry = self.cache.get(record)
                    if entry is not None:
                        entry.reset_TTL(record)
                        record = entry
            else:
                self.cache.add(record)
            self.update_record(now, record)

    def handle_query(self, msg, addr, port):
        out = None
        if port != queryTypes._MDNS_PORT:
            out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA, False)
            for question in msg.questions:
                out.add_question(question)

        for question in msg.questions:
            if question.type_ == queryTypes._TYPE_PTR:
                if question.name == "_services._dns-sd._udp.local.":
                    for serv_type in self.servicetypes.keys():
                        if out is None:
                            out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA)
                        out.add_answer(msg,
                                       DNSPointer("_services._dns-sd._udp.local.",
                                                  queryTypes._TYPE_PTR, queryTypes._CLASS_IN, queryTypes._DNS_TTL, serv_type))

                for service in self.services.values():
                    if question.name == service.type_:
                        if out is None:
                            out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA)
                        out.add_answer(msg,
                                       DNSPointer(service.type_,
                                                  queryTypes._TYPE_PTR, queryTypes._CLASS_IN, queryTypes._DNS_TTL, service.name))
            else:
                try:
                    if out is None:
                        out = DNSOutgoing(queryTypes._FLAGS_QR_RESPONSE | queryTypes._FLAGS_AA)
                    if question.type_ in (queryTypes._TYPE_A, queryTypes._TYPE_ANY):
                        for service in self.services.values():
                            if service.server == question.name.lower():
                                out.add_answer(msg,
                                               DNSAddress(question.name,
                                                          queryTypes._TYPE_A, queryTypes._CLASS_IN | queryTypes._CLASS_UNIQUE,
                                                          queryTypes._DNS_TTL,
                                                          service.address))
                    service = self.services.get(question.name.lower(), None)
                    if not service:
                        continue

                    if question.type_ in (queryTypes._TYPE_SRV, queryTypes._TYPE_ANY):
                        out.add_answer(msg, DNSService(question.name,
                                                       queryTypes._TYPE_SRV, queryTypes._CLASS_IN | queryTypes._CLASS_UNIQUE,
                                                       queryTypes._DNS_TTL, service.priority, service.weight,
                                                       service.port, service.server))
                    if question.type_ in (queryTypes._TYPE_TXT, queryTypes._TYPE_ANY):
                        out.add_answer(msg, DNSText(question.name,
                                                    queryTypes._TYPE_TXT, queryTypes._CLASS_IN | queryTypes._CLASS_UNIQUE,
                                                    queryTypes._DNS_TTL, service.text))
                    if question.type_ == queryTypes._TYPE_SRV:
                        out.add_additional_answer(DNSAddress(service.server,
                                                             queryTypes._TYPE_A, queryTypes._CLASS_IN | queryTypes._CLASS_UNIQUE,
                                                             queryTypes._DNS_TTL, service.address))

                except Exception as e:
                    log.exception('Unknown error: %r', e)
        if out is not None and out.answers:
            out.id = msg.id
            self.send(out, addr, port)

    def close(self):
        if not queryTypes._GLOBAL_DONE:
            queryTypes._GLOBAL_DONE = True
            self.notify_all()
            self.engine.notify()
            self.unregister_all_services()
            for socket_ in [self._listen_socket] + self._respond_sockets:
                socket_.close()


if __name__ == '__main__':
    desc = {'path': '/~home/'}
    info = ServiceInfo("_xxxx._udp.local.",
                       "Melinte._xxxx._udp.local.",
                       socket.inet_aton("192.0.1.2"), 666, 4, 2,
                       desc, "pop.local.")
    info2 = ServiceInfo("_http._tcp.local.",
                        "Andrei._http._tcp.local.",
                        socket.inet_aton("13.0.1.5"), 90, 0, 0,
                        desc, "ix.local.")
    zeroconf = Zeroconf()
    print("Registration of a service...")
    zeroconf.register_service(info)
    zeroconf.register_service(info2)
    try:
        input("Waiting (press Enter to exit)...")
    finally:
        print("\nUnregistering...")
        zeroconf.unregister_service(info2)
        zeroconf.close()
