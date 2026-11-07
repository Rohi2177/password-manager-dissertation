"""Short-lived permissions for one record and one action."""

from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Callable
from dataclasses import dataclass
from secrets import token_urlsafe
from time import monotonic

from password_manager.broker.exceptions import BrokerDeniedError

CAPABILITY_TOKEN_BYTES = 32
DEFAULT_CAPABILITY_TTL_SECONDS = 10.0
MAX_CAPABILITY_TTL_SECONDS = 30.0
MAX_OUTSTANDING_CAPABILITIES = 32
NEW_RECORD_ID = "0" * 32


ALLOWED_CAPABILITY_ACTIONS = frozenset(
    {
        "create_backup",
        "create_record",
        "copy_password",
        "delete_record",
        "edit_record",
        "reveal_password",
        "view_record",
    }
)


@dataclass(frozen=True, slots=True)
class _Capability:
    record_id: str
    action: str
    expires_at: float


def _default_token_factory() -> str:
    return token_urlsafe(CAPABILITY_TOKEN_BYTES)


def _validate_record_id(record_id: object) -> str:
    if not isinstance(record_id, str) or len(record_id) != 32:
        raise BrokerDeniedError("Request denied.")

    try:
        decoded = bytes.fromhex(record_id)

    except ValueError:
        raise BrokerDeniedError("Request denied.") from None

    if len(decoded) != 16 or decoded.hex() != record_id:
        raise BrokerDeniedError("Request denied.")

    return record_id


def _validate_action(action: object) -> str:

    if not isinstance(action, str) or action not in ALLOWED_CAPABILITY_ACTIONS:
        raise BrokerDeniedError("Request denied.")

    return action


def _token_digest(token: object) -> bytes:

    if not isinstance(token, str) or not 32 <= len(token) <= 128 or not token.isascii():
        raise BrokerDeniedError("Request denied.")

    return hashlib.sha256(token.encode("ascii")).digest()


class CapabilityManager:
    """Keep only token digests and atomically invalidate a token on first use."""

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_CAPABILITY_TTL_SECONDS,
        clock: Callable[[], float] = monotonic,
        token_factory: Callable[[], str] = _default_token_factory,
    ) -> None:

        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(float(ttl_seconds))
            or not 0 < float(ttl_seconds) <= MAX_CAPABILITY_TTL_SECONDS
        ):
            raise ValueError("Capability lifetime is outside the accepted range.")

        if not callable(clock) or not callable(token_factory):
            raise TypeError("Capability clock and token factory must be callable.")

        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._token_factory = token_factory
        self._capabilities: dict[bytes, _Capability] = {}

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_seconds

    @property
    def outstanding_count(self) -> int:
        self._purge_expired()
        return len(self._capabilities)

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [digest for digest, item in self._capabilities.items() if now >= item.expires_at]
        for digest in expired:
            del self._capabilities[digest]

    def issue(self, record_id: object, action: object) -> str:

        validated_record_id = _validate_record_id(record_id)
        validated_action = _validate_action(action)
        self._purge_expired()

        if len(self._capabilities) >= MAX_OUTSTANDING_CAPABILITIES:
            raise BrokerDeniedError("Request denied.")

        for _ in range(4):
            token = self._token_factory()
            digest = _token_digest(token)
            if digest not in self._capabilities:
                self._capabilities[digest] = _Capability(
                    record_id=validated_record_id,
                    action=validated_action,
                    expires_at=self._clock() + self._ttl_seconds,
                )

                return token

        raise BrokerDeniedError("Request denied.")

    def consume(
        self,
        token: object,
        record_id: object,
        action: object,
    ) -> None:
        """Remove the token first so an incorrect first use also consumes it."""

        digest = _token_digest(token)
        capability = self._capabilities.pop(digest, None)

        if capability is None:
            raise BrokerDeniedError("Request denied.")

        try:
            validated_record_id = _validate_record_id(record_id)

            validated_action = _validate_action(action)

        except BrokerDeniedError:
            raise BrokerDeniedError("Request denied.") from None

        expired = self._clock() >= capability.expires_at

        wrong_record = not hmac.compare_digest(capability.record_id, validated_record_id)
        wrong_action = not hmac.compare_digest(capability.action, validated_action)

        if expired or wrong_record or wrong_action:
            raise BrokerDeniedError("Request denied.")

    def invalidate_all(self) -> None:
        self._capabilities.clear()
