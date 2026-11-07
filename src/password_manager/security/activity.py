"""Track inactivity without holding any vault data."""

from __future__ import annotations

import math
import time
from collections.abc import Callable

MIN_INACTIVITY_SECONDS = 60.0
MAX_INACTIVITY_SECONDS = 3_600.0


class InactivityGuard:
    """Track activity without holding any vault or credential data."""

    def __init__(
        self,
        timeout_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:

        if not callable(clock):
            raise TypeError("Activity clock must be callable.")

        self._clock = clock
        self._timeout_seconds = 0.0
        self.set_timeout_seconds(timeout_seconds)
        self._last_activity = self._clock()

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    def set_timeout_seconds(self, timeout_seconds: float) -> None:

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not MIN_INACTIVITY_SECONDS <= float(timeout_seconds) <= MAX_INACTIVITY_SECONDS
        ):
            raise ValueError("Inactivity timeout is outside the accepted range.")
        self._timeout_seconds = float(timeout_seconds)

    def mark_activity(self) -> None:
        self._last_activity = self._clock()

    def expired(self) -> bool:
        return self._clock() - self._last_activity >= self._timeout_seconds

    def seconds_remaining(self) -> int:
        remaining = self._timeout_seconds - (self._clock() - self._last_activity)
        return max(0, int(math.ceil(remaining)))
