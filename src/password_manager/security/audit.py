"""Record security events without passwords or account details."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_bytes, token_hex

from password_manager.security.file_permissions import harden_private_file

AUDIT_EVENTS = frozenset(
    {
        "application_closed",
        "application_started",
        "backup_created",
        "backup_restored",
        "broker_closed",
        "capability_approved",
        "capability_denied",
        "clipboard_cleared",
        "clipboard_copied",
        "clipboard_preserved",
        "unlock_failed",
        "unlock_succeeded",
        "unlock_throttled",
        "vault_created",
        "vault_locked_inactivity",
        "vault_locked_emergency",
        "vault_locked_manual",
        "vault_locked_power",
        "vault_locked_session",
        "windows_hello_denied",
        "windows_hello_verified",
    }
)

_AUDIT_VERSION = 1
_KEY_BYTES = 32
_ZERO_MAC = "0" * 64


def _default_log_directory() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")

    if local_app_data:
        return Path(local_app_data) / "PasswordManagerV2" / "logs"
    xdg_state_home = os.environ.get("XDG_STATE_HOME")

    if xdg_state_home:
        return Path(xdg_state_home) / "password-manager-v2" / "logs"
    return Path.home() / ".local" / "state" / "password-manager-v2" / "logs"


def _canonical_entry(entry: dict[str, object]) -> bytes:
    return json.dumps(
        entry,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _load_or_create_key(key_path: Path) -> bytes:

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
        raise OSError("The audit integrity key is invalid.")

    try:
        os.chmod(key_path, 0o600)

    except OSError:
        pass
    harden_private_file(key_path)
    return key


class SecurityAuditLog:
    """Write one process session per file to avoid cross-process chain races."""

    def __init__(
        self,
        source: str,
        log_directory: str | Path | None = None,
        *,
        clock: Callable[[], float] = time.time,
        session_id: str | None = None,
    ) -> None:

        if source not in {"broker", "ui"}:
            raise ValueError("Audit source is invalid.")

        if not callable(clock):
            raise TypeError("Audit clock must be callable.")
        identifier = token_hex(16) if session_id is None else session_id

        if len(identifier) != 32 or any(
            character not in "0123456789abcdef" for character in identifier
        ):
            raise ValueError("Audit session identifier is invalid.")
        directory = (
            _default_log_directory()
            if log_directory is None
            else Path(log_directory).expanduser().resolve(strict=False)
        )

        directory.mkdir(mode=0o700, parents=True, exist_ok=True)

        try:
            os.chmod(directory, 0o700)

        except OSError:
            pass
        self._source = source
        self._session_id = identifier
        self._clock = clock
        self._key = _load_or_create_key(directory / "audit-integrity.key")
        self._path = directory / f"audit-{source}-{identifier}.jsonl"
        self._sequence = 0
        self._previous_mac = _ZERO_MAC
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event: str) -> None:

        if event not in AUDIT_EVENTS:
            raise ValueError("Audit event is not allowlisted.")

        with self._lock:
            self._sequence += 1
            timestamp = datetime.fromtimestamp(self._clock(), tz=UTC).isoformat(
                timespec="milliseconds"
            )

            core: dict[str, object] = {
                "event": event,
                "previous_mac": self._previous_mac,
                "sequence": self._sequence,
                "session": self._session_id,
                "source": self._source,
                "timestamp": timestamp,
                "version": _AUDIT_VERSION,
            }

            mac = hmac.new(self._key, _canonical_entry(core), hashlib.sha256).hexdigest()
            encoded = _canonical_entry({**core, "mac": mac}) + b"\n"
            descriptor = os.open(
                self._path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o600,
            )

            with os.fdopen(descriptor, "ab") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            harden_private_file(self._path)
            self._previous_mac = mac


def verify_audit_log(log_path: str | Path, key_path: str | Path) -> bool:
    """Check the schema, sequence and HMAC chain for one log file."""

    try:
        key = Path(key_path).read_bytes()

        if len(key) != _KEY_BYTES:
            return False
        lines = Path(log_path).read_bytes().splitlines()

        if not lines:
            return False
        previous_mac = _ZERO_MAC
        expected_sequence = 1
        source: str | None = None
        session: str | None = None
        for line in lines:
            value = json.loads(line.decode("ascii"))
            if not isinstance(value, dict) or set(value) != {
                "event",
                "mac",
                "previous_mac",
                "sequence",
                "session",
                "source",
                "timestamp",
                "version",
            }:
                return False
            mac = value.pop("mac")
            if not isinstance(mac, str) or len(mac) != 64:
                return False
            if (
                value.get("event") not in AUDIT_EVENTS
                or value.get("previous_mac") != previous_mac
                or value.get("sequence") != expected_sequence
                or value.get("version") != _AUDIT_VERSION
                or not isinstance(value.get("timestamp"), str)
            ):
                return False
            current_source = value.get("source")
            current_session = value.get("session")

            if current_source not in {"broker", "ui"} or not isinstance(current_session, str):
                return False
            source = current_source if source is None else source
            session = current_session if session is None else session

            if current_source != source or current_session != session:
                return False
            expected_mac = hmac.new(key, _canonical_entry(value), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, expected_mac):
                return False

            previous_mac = mac
            expected_sequence += 1

        return True
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
