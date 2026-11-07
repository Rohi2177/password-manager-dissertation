"""Windows session-lock detector tests with a fake Win32 library."""

import ctypes
import sys
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from password_manager.security.windows_session import is_windows_session_locked


class _FakeWindowsFunction:
    def __init__(self, callback: Callable[..., object]) -> None:

        self._callback = callback
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: object) -> object:

        return self._callback(*args)


@pytest.mark.parametrize(
    ("desktop", "switch_result", "expected"),
    [(123, 1, False), (123, 0, True), (0, 0, True)],
)
def test_windows_session_lock_result(
    monkeypatch: pytest.MonkeyPatch,
    desktop: int,
    switch_result: int,
    expected: bool,
) -> None:

    closed: list[object] = []
    user32 = SimpleNamespace(
        OpenInputDesktop=_FakeWindowsFunction(lambda _flags, _inherit, _access: desktop),
        SwitchDesktop=_FakeWindowsFunction(lambda _desktop: switch_result),
        CloseDesktop=_FakeWindowsFunction(lambda value: closed.append(value) or 1),
    )

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda _name, *, use_last_error: user32,
        raising=False,
    )

    assert is_windows_session_locked() is expected
    assert closed == ([desktop] if desktop else [])
