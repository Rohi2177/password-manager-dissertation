"""Adversarial tests for one-use, one-record Broker permissions."""

from collections.abc import Callable

import pytest

from password_manager.broker.capabilities import (
    MAX_OUTSTANDING_CAPABILITIES,
    CapabilityManager,
)
from password_manager.broker.exceptions import BrokerDeniedError

RECORD_A = "00" * 16
RECORD_B = "11" * 16


class AdjustableClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _sequential_token_factory() -> Callable[[], str]:

    counter = 0

    def make_token() -> str:
        nonlocal counter
        counter += 1
        return f"token-{counter:032d}"

    return make_token


def test_capability_can_be_used_exactly_once() -> None:

    manager = CapabilityManager(token_factory=_sequential_token_factory())
    token = manager.issue(RECORD_A, "view_record")

    manager.consume(token, RECORD_A, "view_record")

    with pytest.raises(BrokerDeniedError, match="Request denied"):
        manager.consume(token, RECORD_A, "view_record")


@pytest.mark.parametrize(
    ("record_id", "action"),
    [
        (RECORD_B, "view_record"),
        (RECORD_A, "reveal_password"),
    ],
)
def test_wrong_binding_burns_capability(record_id: str, action: str) -> None:

    manager = CapabilityManager(token_factory=_sequential_token_factory())
    token = manager.issue(RECORD_A, "view_record")

    with pytest.raises(BrokerDeniedError):
        manager.consume(token, record_id, action)

    with pytest.raises(BrokerDeniedError):
        manager.consume(token, RECORD_A, "view_record")


def test_expired_capability_is_rejected_and_purged() -> None:

    clock = AdjustableClock()
    manager = CapabilityManager(
        ttl_seconds=5,
        clock=clock,
        token_factory=_sequential_token_factory(),
    )

    token = manager.issue(RECORD_A, "view_record")
    clock.now += 5

    assert manager.outstanding_count == 0
    with pytest.raises(BrokerDeniedError):
        manager.consume(token, RECORD_A, "view_record")


def test_outstanding_capability_limit_fails_closed() -> None:

    manager = CapabilityManager(token_factory=_sequential_token_factory())

    for _ in range(MAX_OUTSTANDING_CAPABILITIES):
        manager.issue(RECORD_A, "view_record")

    with pytest.raises(BrokerDeniedError):
        manager.issue(RECORD_A, "view_record")


@pytest.mark.parametrize(
    ("record_id", "action"),
    [
        ("A" * 32, "view_record"),
        ("00", "view_record"),
        (RECORD_A, "bulk_export"),
    ],
)
def test_invalid_capability_binding_is_rejected(record_id: str, action: str) -> None:
    manager = CapabilityManager()
    with pytest.raises(BrokerDeniedError):
        manager.issue(record_id, action)


@pytest.mark.parametrize("ttl", [True, 0, -1, 31, float("inf"), float("nan")])
def test_invalid_capability_lifetime_is_rejected(ttl: object) -> None:

    with pytest.raises(ValueError):
        CapabilityManager(ttl_seconds=ttl)  # type: ignore[arg-type]


def test_lock_invalidates_unused_permissions() -> None:

    manager = CapabilityManager()
    token = manager.issue(RECORD_A, "reveal_password")

    manager.invalidate_all()

    assert manager.outstanding_count == 0
    with pytest.raises(BrokerDeniedError):
        manager.consume(token, RECORD_A, "reveal_password")
