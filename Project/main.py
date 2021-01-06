import os
import re
import sys
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi
from ServiceTypes_find import *


class MainWindow(QMainWindow):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    def __init__(self):
        super(MainWindow, self).__init__()
        ui_path = os.path.join(self.ROOT_DIR, 'UserInterface.ui')
        loadUi(ui_path, self)
        self.file_path = None
        self.serviceTypesBox.addItem("None")
        self.registerServicePopUp = RegisterServicePopUp(self)
        self.errPopUp = EroarePopUp(self)
        self.errPopUp.okButton.clicked.connect(self.errPopUp.delete_close)
        self.addServiceButton.clicked.connect(self.registerServicePopUp.show)
        self.connections = Connections(self)
        self.searchAllButton.clicked.connect(self.connections.find_ServiceTypes)
        self.searchSelectedType.clicked.connect(self.connections.search_SelectedType)
        self.getIPButton.clicked.connect(self.connections.get_IPaddress)
        self.registerServicePopUp.registerButton.clicked.connect(self.connections.verify_register)
        self.removeServiceButton.clicked.connect(self.connections.remove_Service)


class RegisterServicePopUp(QDialog):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    def __init__(self, parent):
        super().__init__(parent=parent)
        self.ui_path = os.path.join(self.ROOT_DIR, 'register.ui')
        loadUi(self.ui_path, self)
        self.file_path = None
        self.cancelButton.clicked.connect(self.delete_close)

    def delete_close(self):
        '''
        self.typeEdit.clear()
        self.nameEdit.clear()
        self.addressEdit.clear()
        self.portEdit.clear()
        self.weightEdit.clear()
        self.priorityEdit.clear()
        self.ttlEdit.clear()
        self.serverEdit.clear()
        '''
        self.close()

    @staticmethod
    def isSignalConnected1(obj, name):
        index = obj.metaObject().indexOfMethod(name)
        if index > -1:
            method = obj.metaObject().method(index)
            if method:
                return obj.isSignalConnected(method)
        return False


class EroarePopUp(QDialog):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    def __init__(self, parent):
        super().__init__(parent=parent)
        self.ui_path = os.path.join(self.ROOT_DIR, 'eroarePopUp.ui')
        loadUi(self.ui_path, self)
        self.file_path = None
        self.okButton.clicked.connect(self.delete_close)

    def delete_close(self):
        self.eroareEdit.clear()
        self.close()

    def __repr__(self):
        return "EROARE"


class MyBrowserListener:
    def __init__(self):
        self.string = ""

    def remove_service(self, zeroconf, type, name):
        self.string += ("Service %s removed\n" % (name,))
        self.string += ('\n')

    def add_service(self, zeroconf, type, name):
        self.string += "Service %s added\n" % (name,)
        self.string += ("    Type is %s\n" % (type,))
        info = zeroconf.get_service_info(type, name)
        if info:
            self.string += ("    Address is %s:%d\n" % (socket.inet_ntoa(info.address),
                                                        info.port))
            self.string += ("    Weight is %d,\n    Priority is %d\n" % (info.weight,
                                                                         info.priority))
            self.string += ("    Server is %s\n" % info.server)
            if info.properties:
                self.string += "    Properties are\n"
                for key, value in info.properties.items():
                    self.string += ("\t%s: %s\n" % (key, value))
        else:
            self.string += "    No info!\n"
        self.string += '\n'


class MyListenerHNResolver:
    def __init__(self, hostName):
        self.string = ""
        self.hostName = hostName

    def remove_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            print(self.hostName)
            print(name)
            if self.hostName == name:
                self.string += ("%s" % (socket.inet_ntoa(info.address)))
        else:
            self.string += "    No info!\n"


class Connections:
    def __init__(self, mainWindow):
        self.mainWindow = mainWindow
        self.zeroconf = None
        self.browser = None
        self.serv_dict = {}

    def find_ServiceTypes(self):
        if self.zeroconf is None:
            self.zeroconf = Zeroconf()
        service_types = ZeroconfServiceTypes.find(zc=self.zeroconf, timeout=0.5)
        self.mainWindow.outputDisplay.appendPlainText("Types of services:")
        self.mainWindow.serviceTypesBox.clear()
        self.mainWindow.serviceTypesBox.addItem("None")
        for j in service_types:
            self.mainWindow.serviceTypesBox.addItem(j)
            self.mainWindow.outputDisplay.appendPlainText("\t%s" % j)
        self.mainWindow.outputDisplay.appendPlainText("\n")

    def search_SelectedType(self):
        type_ = self.mainWindow.serviceTypesBox.currentText()
        if type_ != "None":
            #if self.zeroconf is None:
            #    self.zeroconf = Zeroconf()
            zeroconf = Zeroconf()
            self.mainWindow.outputDisplay.appendPlainText("Browsing services . . . :")
            listener = MyBrowserListener()
            if self.browser is None:
                self.browser = ServiceBrowser(zeroconf, type_, listener)
            time.sleep(3)
            #zeroconf.close()
            #browser.cancel()
            self.mainWindow.outputDisplay.appendPlainText(listener.string)
        else:
            self.mainWindow.errPopUp.show()
            self.mainWindow.errPopUp.eroareEdit.setPlainText("\t\tAtentie!\n"
                                                             "\tNu ati selectat un tip de serviciu.")
        # self.mainWindow.searchSelectedType.setEnabled(True)

    def get_IPaddress(self):
        hostName = self.mainWindow.hostName.text()
        if hostName != "":
            #if self.zeroconf is None:
            zeroconf = Zeroconf()
            self.mainWindow.outputDisplay.appendPlainText("Resolving hostname . . . :")
            listener = MyListenerHNResolver(hostName)
            type_ = re.sub("^[^.]+", '', hostName)
            type_ = type_[1:]

            browser = ServiceBrowser(zeroconf, type_, listener)
            time.sleep(3)
            zeroconf.close()
            #browser.cancel()
            self.mainWindow.ipAddress.setText(listener.string)
            self.mainWindow.outputDisplay.appendPlainText("\t"+listener.string)
        else:
            self.mainWindow.errPopUp.show()
            self.mainWindow.errPopUp.eroareEdit.setPlainText("\t\tAtentie!\n"
                                                             "\tCamp gol.")

    def verify_register(self):
        type_ = re.search("^_[a-zA-Z]+\.((_udp)?|(_tcp)?)\.local\.$",
                          self.mainWindow.registerServicePopUp.typeEdit.text())
        name = re.search("^[a-zA-Z- 0-9_]+\._[a-zA-Z]+\.((_udp)?|(_tcp)?).local\.$",
                         self.mainWindow.registerServicePopUp.nameEdit.text())
        address = re.search("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$",
                            self.mainWindow.registerServicePopUp.addressEdit.text())
        port = re.search("^[0-9]{0,3}$", self.mainWindow.registerServicePopUp.portEdit.text())
        weight = re.search("^[0-9]{0,3}$", self.mainWindow.registerServicePopUp.weightEdit.text())
        priority = re.search("^[0-9]{0,3}$", self.mainWindow.registerServicePopUp.priorityEdit.text())
        ttl = re.search("^[1-9][0-9]{0,4}$", self.mainWindow.registerServicePopUp.ttlEdit.text())
        server = re.search("^[a-zA-Z- 0-9_]+\.local\.$", self.mainWindow.registerServicePopUp.serverEdit.text())
        if type_ is None or name is None or address is None or port is None or weight is None \
                or priority is None or ttl is None or server is None:
            self.mainWindow.errPopUp.show()
            self.mainWindow.errPopUp.eroareEdit.setPlainText("\t\tAtentie!\n"
                                                             "\tNu ati completat un camp sau ati completat un camp gresit!")
        elif not name.string.endswith(type_.string):
            self.mainWindow.errPopUp.show()
            self.mainWindow.errPopUp.eroareEdit.setPlainText("\t\tAtentie!\n"
                                                             "\tNumele serviciului nu se termina cu '%s'!" % type_)
        else:
            info = ServiceInfo(type_=type_.string, name=name.string,
                               address=socket.inet_aton(address.string), port=int(port.string),
                               weight=int(weight.string), priority=int(priority.string), properties={}, server=server.string)
            if self.zeroconf is None:
                self.zeroconf = Zeroconf()
            self.mainWindow.outputDisplay.appendPlainText("Registration of service '%s'" % name.string)
            self.zeroconf.register_service(info, ttl=int(ttl.string))
            self.mainWindow.outputDisplay.appendPlainText("Registration done!\n")
            self.mainWindow.registerServicePopUp.delete_close()
            index = self.mainWindow.servicesBox.findText(name.string)
            if index < 0:
                self.mainWindow.servicesBox.addItem(name.string)
                self.serv_dict[name.string] = info
            '''
            try:
                self.thread = threading.Thread(target=self.kk, args=(info,))
                self.thread.start()
            except RuntimeError:
                print("Eroare la pornirea thread-ului!")

    def kk(self, info):
        zeroconf = Zeroconf()
        print("Registration of a service...")
        zeroconf.register_service(info)
        try:
            input("Waiting (press Enter to exit)...")
        finally:
            print("\nUnregistering...")
            zeroconf.unregister_service(info)
            zeroconf.close()
            '''
    def remove_Service(self):
        index = self.mainWindow.servicesBox.currentIndex()
        if index != -1:
            name = self.mainWindow.servicesBox.currentText()
            self.mainWindow.outputDisplay.appendPlainText("\nUnregistering of service '%s'" % name)
            self.mainWindow.servicesBox.removeItem(index)
            self.zeroconf.unregister_service(self.serv_dict[name])
            #self.zeroconf.close()
            self.mainWindow.outputDisplay.appendPlainText("Unregister done!")
        else:
            self.mainWindow.errPopUp.show()
            self.mainWindow.errPopUp.eroareEdit.setPlainText("\t\tAtentie!\n"
                                                             "\tNu este inregistrat niciun serviciu.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.raise_()
    sys.exit(app.exec_())
