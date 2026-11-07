"""Start the real entry point in a fresh process without opening a vault."""

import os
import subprocess
import sys


def test_application_entry_point_opens_and_closes_cleanly() -> None:

    code = """
import runpy
from pathlib import Path
from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QPushButton
import os
import password_manager.ui.main_window as ui

settings_path = Path(os.environ['LOCALAPPDATA']) / 'startup-settings.ini'
ui.QSettings = lambda *args: QSettings(str(settings_path), QSettings.Format.IniFormat)
original_show = ui.MainWindow.show
opened = []

def show_and_close(window):
    original_show(window)
    assert window.windowTitle() == 'Password Manager'
    assert window._controller is None
    assert window._pages.currentWidget() is window._welcome_page
    labels = {button.text() for button in window._welcome_page.findChildren(QPushButton)}
    assert labels == {
        'Create a new encrypted vault',
        'Open an existing vault',
        'Restore an encrypted backup',
    }
    opened.append(True)
    QTimer.singleShot(50, window.close)

ui.MainWindow.show = show_and_close
try:
    runpy.run_module('password_manager', run_name='__main__')
except SystemExit as result:
    assert result.code == 0
assert opened == [True]
print('Application startup passed')
"""
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run(  # noqa: S603 - fixed test code in this Python interpreter
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Application startup passed" in result.stdout
