"""Start the desktop interface."""

import sys


def main() -> int:

    from PySide6.QtWidgets import QApplication

    from password_manager.config import APP_NAME
    from password_manager.ui.main_window import MainWindow

    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setOrganizationName("University of Sheffield Dissertation")

    window = MainWindow()
    window.show()
    return application.exec()
