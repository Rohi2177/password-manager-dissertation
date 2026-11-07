"""Persistent unlock-throttle policy checks."""

import json
from pathlib import Path

from password_manager.security.throttle import UnlockThrottle


class FakeClock:
    def __init__(self, start: float = 1_000.0) -> None:

        self.now = start

    def __call__(self) -> float:

        return self.now


def test_failed_attempts_use_increasing_delays(tmp_path: Path) -> None:
    clock = FakeClock()
    throttle = UnlockThrottle(tmp_path / "state", clock=clock)
    vault = tmp_path / "fake-vault.pmvault"

    delays = []
    for _attempt in range(10):
        delay = throttle.record_failure(vault)
        delays.append(delay)
        clock.now += delay

    assert delays == [0, 0, 0, 5, 15, 30, 60, 300, 900, 3_600]


def test_counter_and_delay_survive_new_instance(tmp_path: Path) -> None:

    clock = FakeClock()
    state_directory = tmp_path / "state"
    vault = tmp_path / "fake-vault.pmvault"
    first = UnlockThrottle(state_directory, clock=clock)
    for _attempt in range(4):
        first.record_failure(vault)

    restarted = UnlockThrottle(state_directory, clock=clock)

    assert restarted.remaining_seconds(vault) == 5
    clock.now += 5
    assert restarted.remaining_seconds(vault) == 0
    assert restarted.record_failure(vault) == 15


def test_success_reset_removes_only_selected_vault_state(tmp_path: Path) -> None:

    clock = FakeClock()
    throttle = UnlockThrottle(tmp_path / "state", clock=clock)
    first_vault = tmp_path / "first.pmvault"

    second_vault = tmp_path / "second.pmvault"

    for _attempt in range(4):
        throttle.record_failure(first_vault)
        throttle.record_failure(second_vault)

    throttle.reset(first_vault)

    assert throttle.remaining_seconds(first_vault) == 0
    assert throttle.remaining_seconds(second_vault) == 5


def test_tampered_state_fails_closed_without_exposing_path(tmp_path: Path) -> None:
    clock = FakeClock()
    state_directory = tmp_path / "state"
    throttle = UnlockThrottle(state_directory, clock=clock)
    vault = tmp_path / "private-name.pmvault"

    for _attempt in range(4):
        throttle.record_failure(vault)
    state_path = next(state_directory.glob("unlock-*.json"))
    document = json.loads(state_path.read_text(encoding="ascii"))
    document["failures"] = 0
    state_path.write_text(json.dumps(document), encoding="ascii")

    assert throttle.remaining_seconds(vault) == 3_600
    assert "private-name" not in state_path.name
    clock.now += 3_600
    assert throttle.remaining_seconds(vault) == 0
