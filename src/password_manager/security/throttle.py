"""Save failed unlock attempts and increasing delays."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from secrets import token_bytes

from password_manager.security.file_permissions import harden_private_file

_STATE_VERSION = 1
_KEY_BYTES = 32
_MAX_FAILURES = 10_000
_FAIL_CLOSED_SECONDS = 3_600


def _default_state_directory() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")

    if local_app_data:
        return Path(local_app_data) / "PasswordManagerV2" / "security"
    xdg_state_home = os.environ.get("XDG_STATE_HOME")

    if xdg_state_home:
        return Path(xdg_state_home) / "password-manager-v2"
    return Path.home() / ".local" / "state" / "password-manager-v2"


def _delay_for_failures(failures: int) -> int:

    if failures <= 3:
        return 0
    if failures == 4:
        return 5
    if failures == 5:
        return 15
    if failures == 6:
        return 30
    if failures == 7:
        return 60

    if failures == 8:
        return 300

    if failures == 9:
        return 900
    return 3_600


def _vault_tag(vault_path: str | Path) -> str:

    resolved = Path(vault_path).expanduser().resolve(strict=False)
    normalized = os.path.normcase(str(resolved))
    return hashlib.sha256(normalized.encode("utf-8", errors="strict")).hexdigest()


def _canonical_state(version: int, failures: int, blocked_until: int) -> bytes:
    return json.dumps(
        {
            "blocked_until": blocked_until,
            "failures": failures,
            "version": version,
        },
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


@dataclass(frozen=True, slots=True)
class _ThrottleState:
    failures: int = 0
    blocked_until: int = 0


class UnlockThrottle:
    """Persist consecutive failures without storing a vault path or passphrase."""

    def __init__(
        self,
        state_directory: str | Path | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:

        if not callable(clock):
            raise TypeError("Throttle clock must be callable.")
        self._clock = clock
        self._directory = (
            _default_state_directory()
            if state_directory is None
            else Path(state_directory).expanduser().resolve(strict=False)
        )

        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self._directory, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        key_path = self._directory / "unlock-throttle.key"

        try:
            key = key_path.read_bytes()

        except FileNotFoundError:
            key = token_bytes(_KEY_BYTES)

            try:
                descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

            except FileExistsError:
                key = key_path.read_bytes()

            else:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(key)
                    stream.flush()
                    os.fsync(stream.fileno())

        if len(key) != _KEY_BYTES:
            raise OSError("The unlock-throttle integrity key is invalid.")

        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        harden_private_file(key_path)
        return key

    def _state_path(self, vault_path: str | Path) -> Path:
        return self._directory / f"unlock-{_vault_tag(vault_path)}.json"

    def _mac(self, state_bytes: bytes) -> str:

        return hmac.new(self._key, state_bytes, hashlib.sha256).hexdigest()

    def _load(self, vault_path: str | Path) -> _ThrottleState:
        state_path = self._state_path(vault_path)

        try:
            raw = state_path.read_bytes()
        except FileNotFoundError:
            return _ThrottleState()

        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
            if not isinstance(value, dict) or set(value) != {
                "blocked_until",
                "failures",
                "mac",
                "version",
            }:
                raise ValueError
            version = value["version"]
            failures = value["failures"]
            blocked_until = value["blocked_until"]
            mac = value["mac"]
            if (
                type(version) is not int
                or version != _STATE_VERSION
                or type(failures) is not int
                or not 0 <= failures <= _MAX_FAILURES
                or type(blocked_until) is not int
                or blocked_until < 0
                or not isinstance(mac, str)
                or len(mac) != 64
            ):
                raise ValueError
            expected = self._mac(_canonical_state(version, failures, blocked_until))

            if not hmac.compare_digest(mac, expected):
                raise ValueError
            return _ThrottleState(failures, blocked_until)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            now = int(self._clock())
            state = _ThrottleState(_MAX_FAILURES, now + _FAIL_CLOSED_SECONDS)
            try:
                self._write(vault_path, state)
            except OSError:
                pass
            return state

    def _write(self, vault_path: str | Path, state: _ThrottleState) -> None:

        state_path = self._state_path(vault_path)
        state_bytes = _canonical_state(_STATE_VERSION, state.failures, state.blocked_until)
        document = {
            "blocked_until": state.blocked_until,
            "failures": state.failures,
            "mac": self._mac(state_bytes),
            "version": _STATE_VERSION,
        }

        encoded = json.dumps(
            document,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

        temporary = state_path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, state_path)

            try:
                os.chmod(state_path, 0o600)
            except OSError:
                pass
            harden_private_file(state_path)

        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def remaining_seconds(self, vault_path: str | Path) -> int:

        with self._lock:
            state = self._load(vault_path)
            return max(0, state.blocked_until - int(self._clock()))

    def record_failure(self, vault_path: str | Path) -> int:

        with self._lock:
            state = self._load(vault_path)
            failures = min(_MAX_FAILURES, state.failures + 1)
            delay = _delay_for_failures(failures)
            self._write(
                vault_path,
                _ThrottleState(failures, int(self._clock()) + delay),
            )
            return delay

    def reset(self, vault_path: str | Path) -> None:

        with self._lock:
            try:
                self._state_path(vault_path).unlink(missing_ok=True)
            except OSError as error:
                raise OSError("The unlock-throttle state could not be reset.") from error
