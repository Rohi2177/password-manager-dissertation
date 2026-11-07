"""Verified clipboard lifecycle tests using fake non-secret values."""

from collections.abc import Callable

from password_manager.security.clipboard import ClipboardGuard


class FakeBackend:
    def __init__(self) -> None:

        self.text: str | None = None
        self.clears = 0

    def write_text(self, text: str) -> None:

        self.text = text

    def read_text(self) -> str | None:
        return self.text

    def clear(self) -> None:
        self.text = None
        self.clears += 1


class FakeTimer:
    def __init__(self, _delay: float, callback: Callable[[], None]) -> None:

        self.callback = callback
        self.cancelled = False
        self.started = False
        self.daemon = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:

        self.cancelled = True

    def fire(self) -> None:

        if not self.cancelled:
            self.callback()


class FakeTimerFactory:
    def __init__(self) -> None:

        self.timers: list[FakeTimer] = []

    def __call__(self, delay: float, callback: Callable[[], None]) -> FakeTimer:

        timer = FakeTimer(delay, callback)
        self.timers.append(timer)
        return timer


def test_guard_clears_unchanged_value_after_timeout() -> None:

    backend = FakeBackend()
    timers = FakeTimerFactory()
    guard = ClipboardGuard(backend, timeout_seconds=30, timer_factory=timers)

    guard.copy("fake-copied-value")
    timers.timers[-1].fire()

    assert backend.text is None
    assert backend.clears == 1


def test_guard_preserves_newer_user_clipboard_value() -> None:

    backend = FakeBackend()
    timers = FakeTimerFactory()
    guard = ClipboardGuard(backend, timeout_seconds=30, timer_factory=timers)

    guard.copy("fake-copied-value")
    backend.text = "newer harmless text"
    timers.timers[-1].fire()

    assert backend.text == "newer harmless text"
    assert backend.clears == 0


def test_second_copy_invalidates_first_timer() -> None:

    backend = FakeBackend()
    timers = FakeTimerFactory()
    guard = ClipboardGuard(backend, timeout_seconds=30, timer_factory=timers)

    guard.copy("first fake value")
    first_timer = timers.timers[-1]
    guard.copy("second fake value")
    first_timer.fire()

    assert backend.text == "second fake value"
    timers.timers[-1].fire()
    assert backend.text is None


def test_lock_clears_only_matching_value_immediately() -> None:

    backend = FakeBackend()
    timers = FakeTimerFactory()
    guard = ClipboardGuard(backend, timeout_seconds=30, timer_factory=timers)
    guard.copy("fake lock value")

    guard.close()

    assert backend.text is None
    assert backend.clears == 1
    assert timers.timers[-1].cancelled
