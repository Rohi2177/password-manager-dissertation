"""Inactivity-expiry tests independent of the Qt event loop."""

from password_manager.security.activity import InactivityGuard


class FakeClock:
    def __init__(self) -> None:

        self.now = 100.0

    def __call__(self) -> float:

        return self.now


def test_activity_delays_expiry_and_timeout_can_change() -> None:

    clock = FakeClock()
    guard = InactivityGuard(300, clock=clock)
    clock.now += 299
    assert not guard.expired()
    assert guard.seconds_remaining() == 1

    guard.mark_activity()
    clock.now += 60
    assert not guard.expired()

    guard.set_timeout_seconds(60)
    assert guard.expired()
    assert guard.seconds_remaining() == 0
