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
        # self.outputDisplay.appendPlainText("ndsfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdsssss")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.raise_()
    sys.exit(app.exec_())
