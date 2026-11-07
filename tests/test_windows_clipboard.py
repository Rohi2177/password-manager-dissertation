"""Platform-independent checks for the Broker's direct Windows clipboard writer."""

import ctypes
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from password_manager.broker.windows_clipboard import copy_unicode_text


class _FakeWindowsFunction:
    def __init__(self, callback: Callable[..., object]) -> None:

        self._callback = callback
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: object) -> object:

        return self._callback(*args)


def test_copy_unicode_text_transfers_immediate_utf16_data(monkeypatch: Any) -> None:

    buffer = ctypes.create_string_buffer(256)
    expected = "fake-copy-value".encode("utf-16-le") + b"\x00\x00"
    captured: dict[str, object] = {}

    def set_clipboard_data(format_number: object, pointer: object) -> object:
        captured["format"] = format_number
        captured["data"] = ctypes.string_at(pointer, len(expected))
        return pointer

    user32 = SimpleNamespace(
        OpenClipboard=_FakeWindowsFunction(lambda _owner: 1),
        EmptyClipboard=_FakeWindowsFunction(lambda: 1),
        SetClipboardData=_FakeWindowsFunction(set_clipboard_data),
        CloseClipboard=_FakeWindowsFunction(lambda: 1),
    )

    kernel32 = SimpleNamespace(
        GlobalAlloc=_FakeWindowsFunction(lambda _flags, _size: ctypes.addressof(buffer)),
        GlobalLock=_FakeWindowsFunction(lambda handle: handle),
        GlobalUnlock=_FakeWindowsFunction(lambda _handle: 1),
        GlobalFree=_FakeWindowsFunction(lambda _handle: None),
    )

    def fake_windows_library(name: str, *, use_last_error: bool) -> object:

        assert use_last_error is True
        return user32 if name == "user32" else kernel32

    monkeypatch.setattr(ctypes, "WinDLL", fake_windows_library, raising=False)
    copy_unicode_text("fake-copy-value")

    assert captured == {"format": 13, "data": expected}
