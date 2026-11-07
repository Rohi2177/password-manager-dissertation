"""Write and clear clipboard text through Windows."""

from __future__ import annotations

import ctypes
import time

_CF_UNICODE_TEXT = 13
_MAX_CLIPBOARD_TEXT_BYTES = 1_048_576


def _last_error() -> int:

    getter = getattr(ctypes, "get_last_error", None)
    return 0 if getter is None else int(getter())


def copy_unicode_text(text: str) -> None:

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        raise OSError("The Windows clipboard API is unavailable.")

    user32 = windows_library("user32", use_last_error=True)
    kernel32 = windows_library("kernel32", use_last_error=True)

    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = ctypes.c_int
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    gmem_moveable = 0x0002
    encoded = text.encode("utf-16-le") + b"\x00\x00"
    memory_handle = kernel32.GlobalAlloc(gmem_moveable, len(encoded))

    if not memory_handle:
        raise OSError(_last_error(), "Could not allocate Windows clipboard memory.")

    ownership_transferred = False
    clipboard_open = False

    try:
        memory_pointer = kernel32.GlobalLock(memory_handle)

        if not memory_pointer:
            raise OSError(_last_error(), "Could not lock Windows clipboard memory.")

        try:
            ctypes.memmove(memory_pointer, encoded, len(encoded))

        finally:
            kernel32.GlobalUnlock(memory_handle)

        for _attempt in range(10):
            if user32.OpenClipboard(None):
                clipboard_open = True
                break
            time.sleep(0.025)

        if not clipboard_open:
            raise OSError(_last_error(), "Could not open the Windows clipboard.")

        if not user32.EmptyClipboard():
            raise OSError(_last_error(), "Could not clear the Windows clipboard.")

        if not user32.SetClipboardData(_CF_UNICODE_TEXT, memory_handle):
            raise OSError(_last_error(), "Could not write the Windows clipboard.")

        ownership_transferred = True

    finally:
        if clipboard_open:
            user32.CloseClipboard()

        if not ownership_transferred:
            kernel32.GlobalFree(memory_handle)


def read_unicode_text() -> str | None:

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        raise OSError("The Windows clipboard API is unavailable.")
    user32 = windows_library("user32", use_last_error=True)
    kernel32 = windows_library("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int
    kernel32.GlobalSize.argtypes = [ctypes.c_void_p]
    kernel32.GlobalSize.restype = ctypes.c_size_t

    clipboard_open = False

    try:
        for _attempt in range(10):
            if user32.OpenClipboard(None):
                clipboard_open = True
                break
            time.sleep(0.025)

        if not clipboard_open:
            raise OSError(_last_error(), "Could not open the Windows clipboard.")
        memory_handle = user32.GetClipboardData(_CF_UNICODE_TEXT)

        if not memory_handle:
            return None
        size = int(kernel32.GlobalSize(memory_handle))

        if size <= 0 or size > _MAX_CLIPBOARD_TEXT_BYTES or size % 2:
            return None
        memory_pointer = kernel32.GlobalLock(memory_handle)

        if not memory_pointer:
            return None

        try:
            encoded = ctypes.string_at(memory_pointer, size)

        finally:
            kernel32.GlobalUnlock(memory_handle)
        return encoded.decode("utf-16-le", errors="strict").split("\x00", 1)[0]

    finally:
        if clipboard_open:
            user32.CloseClipboard()


def clear_clipboard() -> None:

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        raise OSError("The Windows clipboard API is unavailable.")
    user32 = windows_library("user32", use_last_error=True)
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = ctypes.c_int
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int

    clipboard_open = False

    try:
        for _attempt in range(10):
            if user32.OpenClipboard(None):
                clipboard_open = True
                break
            time.sleep(0.025)

        if not clipboard_open:
            raise OSError(_last_error(), "Could not open the Windows clipboard.")

        if not user32.EmptyClipboard():
            raise OSError(_last_error(), "Could not clear the Windows clipboard.")

    finally:
        if clipboard_open:
            user32.CloseClipboard()
