"""Detect Windows session changes and sleep events."""

from __future__ import annotations

import ctypes
import sys

_WM_POWERBROADCAST = 0x0218
_WM_WTSSESSION_CHANGE = 0x02B1
_PBT_APMSUSPEND = 0x0004
_WTS_CONSOLE_DISCONNECT = 0x0002
_WTS_REMOTE_DISCONNECT = 0x0004
_WTS_SESSION_LOGOFF = 0x0006
_WTS_SESSION_LOCK = 0x0007
_NOTIFY_FOR_THIS_SESSION = 0


def lock_event_for_windows_message(message: int, parameter: int) -> str | None:

    if message == _WM_POWERBROADCAST and parameter == _PBT_APMSUSPEND:
        return "vault_locked_power"

    if message == _WM_WTSSESSION_CHANGE and parameter in {
        _WTS_CONSOLE_DISCONNECT,
        _WTS_REMOTE_DISCONNECT,
        _WTS_SESSION_LOGOFF,
        _WTS_SESSION_LOCK,
    }:
        return "vault_locked_session"
    return None


def message_and_parameter(native_message: int) -> tuple[int, int] | None:

    if sys.platform != "win32" or not native_message:
        return None

    class _Point(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class _Message(ctypes.Structure):
        _fields_ = [
            ("hwnd", ctypes.c_void_p),
            ("message", ctypes.c_uint),
            ("wParam", ctypes.c_size_t),
            ("lParam", ctypes.c_ssize_t),
            ("time", ctypes.c_ulong),
            ("pt", _Point),
            ("lPrivate", ctypes.c_ulong),
        ]

    value = _Message.from_address(native_message)
    return int(value.message), int(value.wParam)


def register_session_notifications(window_handle: int) -> bool:

    if sys.platform != "win32" or not window_handle:
        return False
    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        return False
    wtsapi32 = windows_library("wtsapi32", use_last_error=True)
    wtsapi32.WTSRegisterSessionNotification.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    wtsapi32.WTSRegisterSessionNotification.restype = ctypes.c_int
    return bool(
        wtsapi32.WTSRegisterSessionNotification(
            ctypes.c_void_p(window_handle),
            _NOTIFY_FOR_THIS_SESSION,
        )
    )


def unregister_session_notifications(window_handle: int) -> None:

    if sys.platform != "win32" or not window_handle:
        return
    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        return
    wtsapi32 = windows_library("wtsapi32", use_last_error=True)
    wtsapi32.WTSUnRegisterSessionNotification.argtypes = [ctypes.c_void_p]
    wtsapi32.WTSUnRegisterSessionNotification.restype = ctypes.c_int
    wtsapi32.WTSUnRegisterSessionNotification(ctypes.c_void_p(window_handle))
