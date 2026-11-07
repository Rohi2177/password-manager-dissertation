"""Check whether the Windows desktop is locked."""

from __future__ import annotations

import ctypes
import sys


def is_windows_session_locked() -> bool:

    if sys.platform != "win32":
        return False
    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        return True
    user32 = windows_library("user32", use_last_error=True)
    user32.OpenInputDesktop.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
    user32.OpenInputDesktop.restype = ctypes.c_void_p
    user32.SwitchDesktop.argtypes = [ctypes.c_void_p]
    user32.SwitchDesktop.restype = ctypes.c_int
    user32.CloseDesktop.argtypes = [ctypes.c_void_p]
    user32.CloseDesktop.restype = ctypes.c_int

    desktop_switch = 0x0100
    desktop = user32.OpenInputDesktop(0, 0, desktop_switch)

    if not desktop:
        return True

    try:
        return not bool(user32.SwitchDesktop(desktop))

    finally:
        user32.CloseDesktop(desktop)
