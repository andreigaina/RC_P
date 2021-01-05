import os
import sys
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi


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


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.raise_()
    sys.exit(app.exec_())
