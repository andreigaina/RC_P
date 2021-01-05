import os
import sys
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi
from ServiceTypes_find import *


class MainWindow(QMainWindow):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    def __init__(self):
        super(MainWindow, self).__init__()
        ui_path = os.path.join(self.ROOT_DIR, 'UserInterface.ui')
        print(ui_path)
        loadUi(ui_path, self)
        self.file_path = None
        self.registerServicePopUp = RegisterServicePopUp(self)
        self.addServiceButton.clicked.connect(self.registerServicePopUp.show)
        self.connections = Connections(self)
        self.searchAllButton.clicked.connect(self.connections.find_ServiceTypes)
        self.searchSelectedType.clicked.connect(self.connections.search_SelectedType)
        # self.outputDisplay.appendPlainText("ndsfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdsssss")


class RegisterServicePopUp(QDialog):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    def __init__(self, parent):
        super().__init__(parent=parent)
        self.ui_path = os.path.join(self.ROOT_DIR, 'register.ui')
        loadUi(self.ui_path, self)
        self.file_path = None
        self.cancelButton.clicked.connect(self.delete_close)

    def delete_close(self):
        self.typeEdit.clear()
        self.nameEdit.clear()
        self.addressEdit.clear()
        self.portEdit.clear()
        self.weightEdit.clear()
        self.priorityEdit.clear()
        self.ttlEdit.clear()
        self.serverEdit.clear()
        self.close()

    @staticmethod
    def isSignalConnected1(obj, name):
        index = obj.metaObject().indexOfMethod(name)
        if index > -1:
            method = obj.metaObject().method(index)
            if method:
                return obj.isSignalConnected(method)
        return False

    def __repr__(self):
        return "STUDENTI"


class MyListener(object):
    def __init__(self, mainWindow):
        self.mainWindow = mainWindow
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


class Connections:
    def __init__(self, mainWindow):
        self.mainWindow = mainWindow

    def find_ServiceTypes(self):
        service_types = ZeroconfServiceTypes.find(timeout=0.5)
        self.mainWindow.outputDisplay.appendPlainText("Types of services:")
        self.mainWindow.serviceTypesBox.clear()
        for j in service_types:
            self.mainWindow.serviceTypesBox.addItem(j)
            self.mainWindow.outputDisplay.appendPlainText("\t%s" % j)

    def search_SelectedType(self):

        type_ = self.mainWindow.serviceTypesBox.currentText()
        if type_ != '':
            zeroconf = Zeroconf()
            self.mainWindow.outputDisplay.appendPlainText("Browsing services . . . :")
            listener = MyListener(self.mainWindow)
            browser2 = ServiceBrowser(zeroconf, type_, listener)
            time.sleep(3)
            zeroconf.close()
            self.mainWindow.outputDisplay.appendPlainText(listener.string)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.raise_()
    sys.exit(app.exec_())
