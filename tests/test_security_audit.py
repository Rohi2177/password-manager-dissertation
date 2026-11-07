"""Privacy and tamper-evidence checks for operational logs."""

import json
from pathlib import Path

import pytest

from password_manager.security.audit import SecurityAuditLog, verify_audit_log


def test_audit_log_contains_only_allowlisted_metadata_and_verifies(tmp_path: Path) -> None:

    log = SecurityAuditLog(
        "ui",
        tmp_path,
        clock=lambda: 1_700_000_000.0,
        session_id="12" * 16,
    )

    log.record("application_started")
    log.record("vault_locked_manual")

    lines = log.path.read_text(encoding="ascii").splitlines()
    entries = [json.loads(line) for line in lines]

    assert [entry["sequence"] for entry in entries] == [1, 2]
    assert [entry["event"] for entry in entries] == [
        "application_started",
        "vault_locked_manual",
    ]

    assert set(entries[0]) == {
        "event",
        "mac",
        "previous_mac",
        "sequence",
        "session",
        "source",
        "timestamp",
        "version",
    }

    assert verify_audit_log(log.path, tmp_path / "audit-integrity.key")


def test_modified_audit_event_fails_verification(tmp_path: Path) -> None:

    log = SecurityAuditLog("broker", tmp_path, session_id="34" * 16)
    log.record("unlock_failed")
    original = log.path.read_text(encoding="ascii")
    log.path.write_text(
        original.replace("unlock_failed", "unlock_succeeded"),
        encoding="ascii",
    )

    assert not verify_audit_log(log.path, tmp_path / "audit-integrity.key")


def test_windows_hello_decisions_are_safe_allowlisted_events(tmp_path: Path) -> None:

    log = SecurityAuditLog("broker", tmp_path, session_id="78" * 16)

    log.record("windows_hello_verified")
    log.record("windows_hello_denied")

    entries = [json.loads(line) for line in log.path.read_text(encoding="ascii").splitlines()]
    assert [entry["event"] for entry in entries] == [
        "windows_hello_verified",
        "windows_hello_denied",
    ]

    assert verify_audit_log(log.path, tmp_path / "audit-integrity.key")


def test_arbitrary_or_sensitive_event_names_are_rejected(tmp_path: Path) -> None:
    log = SecurityAuditLog("ui", tmp_path, session_id="56" * 16)

    with pytest.raises(ValueError, match="allowlisted"):
        log.record("password=fake-secret")
