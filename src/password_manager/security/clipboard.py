"""Clear copied text only when the clipboard still contains the same value."""

from __future__ import annotations

import hashlib
import hmac
import math
import threading
from collections.abc import Callable
from typing import Protocol

DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30.0
MIN_CLIPBOARD_CLEAR_SECONDS = 5.0
MAX_CLIPBOARD_CLEAR_SECONDS = 120.0


class ClipboardBackend(Protocol):
    def write_text(self, text: str) -> None: ...

    def read_text(self) -> str | None: ...

    def clear(self) -> None: ...


class CancellableTimer(Protocol):
    daemon: bool

    def start(self) -> None: ...

    def cancel(self) -> None: ...


TimerFactory = Callable[[float, Callable[[], None]], CancellableTimer]


def _timer_factory(delay: float, callback: Callable[[], None]) -> CancellableTimer:
    return threading.Timer(delay, callback)


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8", errors="strict")).digest()


class ClipboardGuard:
    """Copy through a backend and clear later only if the same value remains."""

    def __init__(
        self,
        backend: ClipboardBackend,
        *,
        timeout_seconds: float = DEFAULT_CLIPBOARD_CLEAR_SECONDS,
        timer_factory: TimerFactory = _timer_factory,
        event_sink: Callable[[str], None] | None = None,
    ) -> None:

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not MIN_CLIPBOARD_CLEAR_SECONDS
            <= float(timeout_seconds)
            <= MAX_CLIPBOARD_CLEAR_SECONDS
        ):
            raise ValueError("Clipboard timeout is outside the accepted range.")

        if not callable(timer_factory):
            raise TypeError("Clipboard timer factory must be callable.")
        self._backend = backend
        self._timeout_seconds = float(timeout_seconds)
        self._timer_factory = timer_factory
        self._event_sink = event_sink
        self._lock = threading.Lock()
        self._digest: bytes | None = None
        self._timer: CancellableTimer | None = None
        self._generation = 0

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    def copy(self, text: str) -> None:

        if not isinstance(text, str) or not text:
            raise ValueError("Clipboard text must not be empty.")

        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._backend.write_text(text)

            if self._event_sink is not None:
                self._event_sink("clipboard_copied")
            self._digest = _digest(text)
            self._generation += 1
            generation = self._generation
            timer = self._timer_factory(
                self._timeout_seconds,
                lambda: self._clear_generation(generation),
            )
            timer.daemon = True
            self._timer = timer
            timer.start()

    def _clear_generation(self, generation: int) -> None:
        with self._lock:
            if generation != self._generation or self._digest is None:
                return
            expected = self._digest

            try:
                current = self._backend.read_text()

                if current is not None and hmac.compare_digest(_digest(current), expected):
                    self._backend.clear()
                    if self._event_sink is not None:
                        self._event_sink("clipboard_cleared")

                elif self._event_sink is not None:
                    self._event_sink("clipboard_preserved")

            finally:
                if generation == self._generation:
                    self._digest = None
                    self._timer = None

    def clear_now_if_unchanged(self) -> None:

        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            expected = self._digest
            self._digest = None
            self._generation += 1

            if expected is None:
                return
            current = self._backend.read_text()

            if current is not None and hmac.compare_digest(_digest(current), expected):
                self._backend.clear()

                if self._event_sink is not None:
                    self._event_sink("clipboard_cleared")

            elif self._event_sink is not None:
                self._event_sink("clipboard_preserved")

    def close(self) -> None:
        self.clear_now_if_unchanged()
