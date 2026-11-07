"""Check Broker permissions using fake records in an encrypted vault."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from approval_support import OneShotApprovalPolicy

from password_manager.broker.capabilities import NEW_RECORD_ID, CapabilityManager
from password_manager.broker.protocol import BROKER_PROTOCOL_VERSION
from password_manager.broker.service import BrokerService
from password_manager.core import Argon2idParameters, CredentialData
from password_manager.core.crypto import MIN_ARGON2_MEMORY_KIB
from password_manager.storage import VaultSession, create_vault, open_vault

FAKE_MASTER_PASSPHRASE = "broker demonstration master phrase 2026"  # noqa: S105
FAKE_PASSWORD = "broker-fake-password-never-use"  # noqa: S105
FAKE_NEW_PASSWORD = "new-generated-fake-password"  # noqa: S105
FAST_TEST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


def _credential() -> CredentialData:
    return CredentialData(
        title="Broker Example",
        website="https://broker.example.invalid/login",
        username="fake.user@example.invalid",
        password=FAKE_PASSWORD,
        notes="Fake Broker test record",
    )


def _credential_payload(*, password: object = FAKE_NEW_PASSWORD) -> dict[str, object]:
    return {
        "notes": "Fake vault notes",
        "password": password,
        "title": "vault Example",
        "username": "test.user@example.invalid",
        "website": "https://test.example.invalid",
    }


def _message(operation: str, payload: dict[str, object], suffix: int = 1) -> dict[str, object]:
    return {
        "operation": operation,
        "payload": payload,
        "protocol": BROKER_PROTOCOL_VERSION,
        "request_id": f"{suffix:032x}",
    }


@pytest.fixture
def vault_and_record(tmp_path: Path) -> Iterator[tuple[VaultSession, str]]:

    vault = create_vault(
        tmp_path / "broker-service.vault.sqlite3",
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    )

    record_id = vault.add_credential(_credential())
    yield vault, record_id
    if vault.is_open:
        vault.close()


def test_ping_identifies_broker_process_and_lock_state(
    vault_and_record: tuple[VaultSession, str],
) -> None:
    vault, _record_id = vault_and_record
    service = BrokerService(vault, pid_provider=lambda: 4321)

    response = service.handle_message(_message("ping", {}))

    assert response["ok"] is True
    assert response["result"] == {"broker_pid": 4321, "locked": False}
    service.close()


def test_summary_page_never_contains_password_or_notes(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, record_id = vault_and_record
    service = BrokerService(vault)

    response = service.handle_message(_message("list_summaries", {"limit": 10, "offset": 0}))
    serialized = repr(response)

    assert response["ok"] is True
    assert record_id in serialized
    assert FAKE_PASSWORD not in serialized
    assert _credential().notes not in serialized
    service.close()


def test_default_policy_denies_secret_capability(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, record_id = vault_and_record
    service = BrokerService(vault)

    response = service.handle_message(
        _message(
            "request_capability",
            {"action": "reveal_password", "record_id": record_id},
        )
    )

    assert response["ok"] is False
    assert response["error"] == {"code": "denied", "message": "Request denied."}
    service.close()


def test_one_shot_policy_validates_and_counts_approvals() -> None:
    record_id = "12" * 16
    policy = OneShotApprovalPolicy([(record_id, "view_record"), (record_id, "view_record")])

    assert policy.approve(record_id, "view_record")
    assert policy.approve(record_id, "view_record")
    assert not policy.approve(record_id, "view_record")

    with pytest.raises(ValueError, match="Invalid"):
        OneShotApprovalPolicy([("bad", "view_record")])
    with pytest.raises(ValueError, match="Too many"):
        OneShotApprovalPolicy([(record_id, "view_record")] * 129)


def test_approved_capability_returns_only_one_requested_record(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(record_id, "view_record")]),
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "view_record", "record_id": record_id},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]

    used = service.handle_message(
        _message(
            "use_capability",
            {"action": "view_record", "record_id": record_id, "token": token},
            suffix=2,
        )
    )

    assert used["ok"] is True
    assert used["result"]["record"]["record_id"] == record_id  # type: ignore[index]
    assert FAKE_PASSWORD not in repr(used)
    service.close()


def test_replayed_capability_is_denied(vault_and_record: tuple[VaultSession, str]) -> None:
    vault, record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(record_id, "reveal_password")]),
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "reveal_password", "record_id": record_id},
        )
    )
    token = issued["result"]["token"]  # type: ignore[index]
    payload = {"action": "reveal_password", "record_id": record_id, "token": token}

    first = service.handle_message(_message("use_capability", payload, suffix=2))
    replay = service.handle_message(_message("use_capability", payload, suffix=3))

    assert first["result"] == {"password": FAKE_PASSWORD, "record_id": record_id}
    assert replay["error"] == {"code": "denied", "message": "Request denied."}
    service.close()


def test_modified_action_burns_capability(vault_and_record: tuple[VaultSession, str]) -> None:
    vault, record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(record_id, "view_record")]),
    )
    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "view_record", "record_id": record_id},
        )
    )
    token = issued["result"]["token"]  # type: ignore[index]

    modified = service.handle_message(
        _message(
            "use_capability",
            {"action": "reveal_password", "record_id": record_id, "token": token},
            suffix=2,
        )
    )

    correct_after_modification = service.handle_message(
        _message(
            "use_capability",
            {"action": "view_record", "record_id": record_id, "token": token},
            suffix=3,
        )
    )

    assert modified["error"]["code"] == "denied"  # type: ignore[index]
    assert correct_after_modification["error"]["code"] == "denied"  # type: ignore[index]
    service.close()


def test_expired_capability_is_denied(vault_and_record: tuple[VaultSession, str]) -> None:

    vault, record_id = vault_and_record
    now = 10.0

    def clock() -> float:

        return now

    manager = CapabilityManager(ttl_seconds=1, clock=clock)
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(record_id, "view_record")]),
        capability_manager=manager,
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "view_record", "record_id": record_id},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]
    now = 11.0

    expired = service.handle_message(
        _message(
            "use_capability",
            {"action": "view_record", "record_id": record_id, "token": token},
            suffix=2,
        )
    )

    assert expired["error"]["code"] == "denied"  # type: ignore[index]
    service.close()


@pytest.mark.parametrize("operation", ["bulk_export", "dump_passwords", "get_all_records"])
def test_bulk_operations_do_not_exist(
    vault_and_record: tuple[VaultSession, str], operation: str
) -> None:
    vault, _record_id = vault_and_record
    service = BrokerService(vault)

    response = service.handle_message(_message(operation, {}))

    assert response["error"] == {"code": "invalid_request", "message": "Invalid request."}
    service.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"limit": 0, "offset": 0},
        {"limit": 51, "offset": 0},
        {"limit": 10, "offset": -1},
        {"limit": 10, "offset": True},
        {"limit": 10, "offset": 0, "extra": True},
    ],
)
def test_invalid_summary_pages_are_rejected(
    vault_and_record: tuple[VaultSession, str],
    payload: dict[str, object],
) -> None:

    vault, _record_id = vault_and_record
    service = BrokerService(vault)

    response = service.handle_message(_message("list_summaries", payload))

    assert response["error"] == {
        "code": "invalid_request",
        "message": "Invalid request.",
    }

    service.close()


def test_closed_vault_or_unexpected_error_locks_broker(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, _record_id = vault_and_record
    service = BrokerService(vault)
    vault.close()

    response = service.handle_message(_message("list_summaries", {"limit": 10, "offset": 0}))

    assert response["error"]["code"] == "internal_error"  # type: ignore[index]
    assert service.is_locked


def test_unexpected_handler_failure_locks_broker(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, _record_id = vault_and_record

    def broken_pid_provider() -> int:
        raise RuntimeError("Synthetic safe test failure")

    service = BrokerService(vault, pid_provider=broken_pid_provider)
    response = service.handle_message(_message("ping", {}))

    assert response["error"]["code"] == "internal_error"  # type: ignore[index]
    assert service.is_locked


def test_lock_invalidates_session(vault_and_record: tuple[VaultSession, str]) -> None:
    vault, _record_id = vault_and_record
    service = BrokerService(vault)

    locked = service.handle_message(_message("lock", {}))
    after_lock = service.handle_message(
        _message("list_summaries", {"limit": 10, "offset": 0}, suffix=2)
    )

    assert locked["result"] == {"locked": True}
    assert after_lock["error"] == {"code": "locked", "message": "Broker is locked."}


def test_create_credential_requires_one_shot_approval(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, _record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(NEW_RECORD_ID, "create_record")]),
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "create_record", "record_id": NEW_RECORD_ID},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]

    created = service.handle_message(
        _message(
            "use_capability",
            {
                "action": "create_record",
                "credential": _credential_payload(),
                "record_id": NEW_RECORD_ID,
                "token": token,
            },
            suffix=2,
        )
    )

    assert created["ok"] is True
    summary = created["result"]["summary"]  # type: ignore[index]
    assert isinstance(summary, dict)
    new_record_id = summary["record_id"]
    assert isinstance(new_record_id, str)
    assert vault.get_credential(new_record_id).data.password == FAKE_NEW_PASSWORD
    assert FAKE_NEW_PASSWORD not in repr(created)
    service.close()


def test_create_backup_requires_one_shot_approval_and_stays_encrypted(
    vault_and_record: tuple[VaultSession, str],
    tmp_path: Path,
) -> None:

    vault, record_id = vault_and_record
    destination = tmp_path / "broker-created-backup.pmvault-backup"
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(NEW_RECORD_ID, "create_backup")]),
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "create_backup", "record_id": NEW_RECORD_ID},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]

    created = service.handle_message(
        _message(
            "use_capability",
            {
                "action": "create_backup",
                "destination": str(destination.absolute()),
                "record_id": NEW_RECORD_ID,
                "token": token,
            },
            suffix=2,
        )
    )

    assert created["result"] == {"backup_created": True}
    assert destination.is_file()
    assert FAKE_PASSWORD.encode() not in destination.read_bytes()
    with open_vault(destination, FAKE_MASTER_PASSPHRASE) as backup:
        assert backup.get_credential(record_id).data.password == FAKE_PASSWORD
    service.close()


def test_relative_backup_destination_is_rejected(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, _record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(NEW_RECORD_ID, "create_backup")]),
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "create_backup", "record_id": NEW_RECORD_ID},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]
    response = service.handle_message(
        _message(
            "use_capability",
            {
                "action": "create_backup",
                "destination": "relative-backup.pmvault",
                "record_id": NEW_RECORD_ID,
                "token": token,
            },
            suffix=2,
        )
    )

    assert response["error"] == {
        "code": "invalid_request",
        "message": "Invalid request.",
    }
    service.close()


def test_edit_preserves_blank_password_then_delete_removes_record(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy(
            [(record_id, "edit_record"), (record_id, "delete_record")]
        ),
    )

    edit_issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "edit_record", "record_id": record_id},
        )
    )

    edit_token = edit_issued["result"]["token"]  # type: ignore[index]
    edited = service.handle_message(
        _message(
            "use_capability",
            {
                "action": "edit_record",
                "credential": _credential_payload(password=None),
                "record_id": record_id,
                "token": edit_token,
            },
            suffix=2,
        )
    )

    assert edited["ok"] is True
    assert vault.get_credential(record_id).data.password == FAKE_PASSWORD
    assert vault.get_credential(record_id).data.title == "vault Example"

    delete_issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "delete_record", "record_id": record_id},
            suffix=3,
        )
    )

    delete_token = delete_issued["result"]["token"]  # type: ignore[index]
    deleted = service.handle_message(
        _message(
            "use_capability",
            {
                "action": "delete_record",
                "record_id": record_id,
                "token": delete_token,
            },
            suffix=4,
        )
    )

    assert deleted["result"] == {"deleted": True, "record_id": record_id}
    assert vault.list_credentials() == []
    service.close()


def test_broker_writes_copy_without_returning_password(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, record_id = vault_and_record
    clipboard: list[str] = []
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(record_id, "copy_password")]),
        clipboard_writer=clipboard.append,
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "copy_password", "record_id": record_id},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]
    copied = service.handle_message(
        _message(
            "use_capability",
            {"action": "copy_password", "record_id": record_id, "token": token},
            suffix=2,
        )
    )

    assert clipboard == [FAKE_PASSWORD]
    assert copied["result"] == {"copied": True, "record_id": record_id}
    assert FAKE_PASSWORD not in repr(copied)
    service.close()


def test_search_returns_only_safe_matching_summaries(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, record_id = vault_and_record
    service = BrokerService(vault)

    matching = service.handle_message(
        _message(
            "search_summaries",
            {"limit": 50, "offset": 0, "query": "Fake Broker test"},
        )
    )

    missing = service.handle_message(
        _message(
            "search_summaries",
            {"limit": 50, "offset": 0, "query": "does-not-match"},
            suffix=2,
        )
    )

    assert matching["result"]["total"] == 1  # type: ignore[index]
    assert record_id in repr(matching)
    assert FAKE_PASSWORD not in repr(matching)
    assert _credential().notes not in repr(matching)
    assert missing["result"]["summaries"] == []  # type: ignore[index]
    service.close()


def test_malformed_create_burns_capability_without_mutation(
    vault_and_record: tuple[VaultSession, str],
) -> None:

    vault, _record_id = vault_and_record
    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(NEW_RECORD_ID, "create_record")]),
    )

    issued = service.handle_message(
        _message(
            "request_capability",
            {"action": "create_record", "record_id": NEW_RECORD_ID},
        )
    )

    token = issued["result"]["token"]  # type: ignore[index]
    malformed_payload = {
        "action": "create_record",
        "record_id": NEW_RECORD_ID,
        "token": token,
    }

    malformed = service.handle_message(_message("use_capability", malformed_payload, suffix=2))
    replay = service.handle_message(
        _message(
            "use_capability",
            {
                **malformed_payload,
                "credential": _credential_payload(),
            },
            suffix=3,
        )
    )

    assert malformed["error"]["code"] == "denied"  # type: ignore[index]
    assert replay["error"]["code"] == "denied"  # type: ignore[index]
    assert len(vault.list_credentials()) == 1
    service.close()


def test_permission_for_one_record_cannot_reveal_another(
    vault_and_record: tuple[VaultSession, str],
) -> None:
    vault, first_id = vault_and_record
    second_id = vault.add_credential(
        CredentialData("Second account", "", "", "second-fake-password")
    )

    service = BrokerService(
        vault,
        approval_policy=OneShotApprovalPolicy([(first_id, "reveal_password")]),
    )

    issued = service.handle_message(
        _message("request_capability", {"action": "reveal_password", "record_id": first_id})
    )

    token = issued["result"]["token"]  # type: ignore[index]

    wrong_record = service.handle_message(
        _message(
            "use_capability",
            {"action": "reveal_password", "record_id": second_id, "token": token},
            suffix=2,
        )
    )

    retry = service.handle_message(
        _message(
            "use_capability",
            {"action": "reveal_password", "record_id": first_id, "token": token},
            suffix=3,
        )
    )

    assert wrong_record["error"] == {"code": "denied", "message": "Request denied."}
    assert retry["error"] == {"code": "denied", "message": "Request denied."}
    assert "second-fake-password" not in repr(wrong_record)
    service.close()
