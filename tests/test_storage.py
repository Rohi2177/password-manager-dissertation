"""Security and lifecycle tests for the encrypted SQLite vault."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from password_manager.core.crypto import (
    MIN_ARGON2_MEMORY_KIB,
    Argon2idParameters,
)
from password_manager.core.models import CredentialData, CredentialValidationError
from password_manager.core.passphrases import PassphrasePolicyError
from password_manager.storage import (
    RecordNotFoundError,
    VaultAlreadyExistsError,
    VaultClosedError,
    VaultFormatError,
    VaultIntegrityError,
    VaultNotFoundError,
    VaultSession,
    VaultStorageError,
    VaultUnlockError,
    create_vault,
    open_vault,
    restore_vault_backup,
)

FAKE_MASTER_PASSPHRASE = "dissertation-only master phrase 2026"  # noqa: S105
WRONG_FAKE_MASTER_PASSPHRASE = "different dissertation phrase 2026"  # noqa: S105
FAKE_PASSWORD = "demo-password-never-use"  # noqa: S105
UPDATED_FAKE_PASSWORD = "new-fake-value"  # noqa: S105
FAST_TEST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


def _credential(*, title: str = "Example Bank", password: str = FAKE_PASSWORD) -> CredentialData:

    return CredentialData(
        title=title,
        website="https://example.invalid/login",
        username="demo.user@example.invalid",
        password=password,
        notes="Fake test record only",
    )


@pytest.fixture
def unlocked_vault(tmp_path: Path) -> Iterator[VaultSession]:

    session = create_vault(
        tmp_path / "test.vault.sqlite3",
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    )

    yield session
    session.close()


def test_create_add_close_reopen_and_read(tmp_path: Path) -> None:

    vault_path = tmp_path / "round-trip.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        record_id = session.add_credential(_credential())
        original_vault_id = session.vault_id

    with open_vault(vault_path, FAKE_MASTER_PASSPHRASE) as reopened:
        record = reopened.get_credential(record_id)
        assert reopened.vault_id == original_vault_id
        assert record.version == 1
        assert record.data == _credential()
        assert reopened.verify_integrity() == 1


def test_default_argon2id_profile_creates_and_reopens_vault(tmp_path: Path) -> None:

    vault_path = tmp_path / "default-profile.vault.sqlite3"

    with create_vault(vault_path, FAKE_MASTER_PASSPHRASE):
        pass

    with open_vault(vault_path, FAKE_MASTER_PASSPHRASE) as reopened:
        assert reopened.verify_integrity() == 0

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        stored_parameters = connection.execute(
            "SELECT argon2_memory_kib, argon2_time_cost, argon2_parallelism FROM vault_header"
        ).fetchone()
    assert stored_parameters == (64 * 1024, 3, 1)


def test_sensitive_fields_do_not_appear_in_raw_database(tmp_path: Path) -> None:

    vault_path = tmp_path / "no-plaintext.vault.sqlite3"
    credential = _credential()
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        session.add_credential(credential)

    raw_database = vault_path.read_bytes()
    for sensitive_value in (
        credential.title,
        credential.website,
        credential.username,
        credential.password,
        credential.notes,
        FAKE_MASTER_PASSPHRASE,
    ):
        assert sensitive_value.encode("utf-8") not in raw_database


def test_header_stores_public_parameters_but_not_live_keys(tmp_path: Path) -> None:

    vault_path = tmp_path / "header.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        row = connection.execute(
            "SELECT kdf_name, argon2_memory_kib, argon2_time_cost, "
            "argon2_parallelism, length(salt), length(wrapped_key_ciphertext) "
            "FROM vault_header"
        ).fetchone()
    assert row == ("argon2id", MIN_ARGON2_MEMORY_KIB, 2, 1, 16, 48)


def test_wrong_master_passphrase_has_generic_unlock_failure(tmp_path: Path) -> None:
    vault_path = tmp_path / "wrong-passphrase.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass

    with pytest.raises(VaultUnlockError, match="Unable to unlock"):
        open_vault(vault_path, WRONG_FAKE_MASTER_PASSPHRASE)


def test_crud_updates_versions_and_manifest(unlocked_vault: VaultSession) -> None:

    first_id = unlocked_vault.add_credential(_credential(title="First"))
    second_id = unlocked_vault.add_credential(_credential(title="Second"))

    records = unlocked_vault.list_credentials()
    assert {record.record_id for record in records} == {first_id, second_id}

    updated_data = _credential(title="First Updated", password=UPDATED_FAKE_PASSWORD)
    updated = unlocked_vault.update_credential(first_id, updated_data)
    assert updated.version == 2
    assert unlocked_vault.get_credential(first_id).data == updated_data

    unlocked_vault.delete_credential(second_id)
    assert [record.record_id for record in unlocked_vault.list_credentials()] == [first_id]
    with pytest.raises(RecordNotFoundError):
        unlocked_vault.get_credential(second_id)


def test_search_is_normalized_case_insensitive_and_excludes_password(
    unlocked_vault: VaultSession,
) -> None:

    matching_id = unlocked_vault.add_credential(
        CredentialData(
            title="Caf\u00e9 Account",
            website="https://example.invalid/login",
            username="Search.Target@unique.invalid",
            password="secret-query-must-not-match",  # noqa: S106
            notes="Research demonstration",
        )
    )

    unlocked_vault.add_credential(_credential(title="Different Record"))

    assert [record.record_id for record in unlocked_vault.search_credentials("CAFE\u0301")] == [
        matching_id
    ]
    assert [record.record_id for record in unlocked_vault.search_credentials("search.target")] == [
        matching_id
    ]
    assert unlocked_vault.search_credentials("secret-query-must-not-match") == []
    assert len(unlocked_vault.search_credentials("  ")) == 2


@pytest.mark.parametrize("query", [object(), "x" * 201])
def test_invalid_search_query_is_rejected(
    unlocked_vault: VaultSession,
    query: object,
) -> None:

    with pytest.raises(CredentialValidationError):
        unlocked_vault.search_credentials(query)  # type: ignore[arg-type]


def test_encrypted_backup_round_trip_contains_no_plaintext(tmp_path: Path) -> None:

    vault_path = tmp_path / "source.vault.sqlite3"
    backup_path = tmp_path / "backup.vault.sqlite3"
    credential = _credential(title="Backup Example")
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        record_id = session.add_credential(credential)
        assert session.create_encrypted_backup(backup_path) == backup_path.absolute()

    with open_vault(backup_path, FAKE_MASTER_PASSPHRASE) as backup:
        assert backup.get_credential(record_id).data == credential
        assert backup.verify_integrity() == 1

    raw_backup = backup_path.read_bytes()
    for sensitive_value in (
        credential.title,
        credential.website,
        credential.username,
        credential.password,
        credential.notes,
        FAKE_MASTER_PASSPHRASE,
    ):
        assert sensitive_value.encode("utf-8") not in raw_backup


def test_backup_never_overwrites_existing_destination(unlocked_vault: VaultSession) -> None:

    destination = unlocked_vault.path.parent / "existing-backup.sqlite3"
    destination.write_bytes(b"keep this existing file")

    with pytest.raises(VaultAlreadyExistsError):
        unlocked_vault.create_encrypted_backup(destination)
    assert destination.read_bytes() == b"keep this existing file"


def test_restore_verifies_backup_and_creates_new_vault(tmp_path: Path) -> None:

    source_path = tmp_path / "source.vault.sqlite3"
    backup_path = tmp_path / "backup.vault.sqlite3"
    restored_path = tmp_path / "restored.vault.sqlite3"
    with create_vault(
        source_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as source:
        record_id = source.add_credential(_credential(title="Restore Example"))
        source.create_encrypted_backup(backup_path)

    with restore_vault_backup(
        backup_path,
        restored_path,
        FAKE_MASTER_PASSPHRASE,
    ) as restored:
        assert restored.get_credential(record_id).data.title == "Restore Example"
        assert restored.verify_integrity() == 1


def test_restore_failure_does_not_create_destination(tmp_path: Path) -> None:
    backup_path = tmp_path / "backup.vault.sqlite3"
    destination = tmp_path / "must-not-exist.sqlite3"
    with create_vault(
        backup_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass

    with pytest.raises(VaultUnlockError):
        restore_vault_backup(
            backup_path,
            destination,
            WRONG_FAKE_MASTER_PASSPHRASE,
        )

    assert not destination.exists()


def test_update_uses_a_fresh_nonce(unlocked_vault: VaultSession) -> None:

    record_id = unlocked_vault.add_credential(_credential())
    with closing(sqlite3.connect(unlocked_vault.path)) as connection, connection:
        original_nonce = connection.execute(
            "SELECT nonce FROM credentials WHERE record_id = ?",
            (bytes.fromhex(record_id),),
        ).fetchone()[0]

    unlocked_vault.update_credential(record_id, _credential(title="Updated"))
    with closing(sqlite3.connect(unlocked_vault.path)) as connection, connection:
        updated_nonce = connection.execute(
            "SELECT nonce FROM credentials WHERE record_id = ?",
            (bytes.fromhex(record_id),),
        ).fetchone()[0]

    assert original_nonce != updated_nonce


def test_manifest_revision_changes_with_every_write(unlocked_vault: VaultSession) -> None:

    record_id = unlocked_vault.add_credential(_credential())
    unlocked_vault.update_credential(record_id, _credential(title="Updated"))
    unlocked_vault.delete_credential(record_id)

    with closing(sqlite3.connect(unlocked_vault.path)) as connection, connection:
        revision = connection.execute("SELECT revision FROM vault_manifest").fetchone()[0]
    assert revision == 3


def test_ciphertext_tampering_is_detected_on_open(tmp_path: Path) -> None:

    vault_path = tmp_path / "tampered-ciphertext.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        session.add_credential(_credential())

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        ciphertext = bytearray(
            connection.execute("SELECT ciphertext FROM credentials").fetchone()[0]
        )

        ciphertext[-1] ^= 1
        connection.execute("UPDATE credentials SET ciphertext = ?", (bytes(ciphertext),))

    with pytest.raises(VaultIntegrityError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_deleted_record_is_detected_by_manifest(tmp_path: Path) -> None:

    vault_path = tmp_path / "deleted-record.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        session.add_credential(_credential())

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute("DELETE FROM credentials")

    with pytest.raises(VaultIntegrityError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_inserted_unknown_record_is_detected_by_manifest(tmp_path: Path) -> None:
    vault_path = tmp_path / "inserted-record.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        session.add_credential(_credential())

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        version, nonce, ciphertext = connection.execute(
            "SELECT record_version, nonce, ciphertext FROM credentials LIMIT 1"
        ).fetchone()

        connection.execute(
            "INSERT INTO credentials(record_id, record_version, nonce, ciphertext) "
            "VALUES (?, ?, ?, ?)",
            (b"x" * 16, version, nonce, ciphertext),
        )

    with pytest.raises(VaultIntegrityError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_single_record_rollback_is_detected(tmp_path: Path) -> None:

    vault_path = tmp_path / "record-rollback.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as session:
        record_id = session.add_credential(_credential(title="Original"))

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        old_row = connection.execute(
            "SELECT record_version, nonce, ciphertext FROM credentials WHERE record_id = ?",
            (bytes.fromhex(record_id),),
        ).fetchone()

    with open_vault(vault_path, FAKE_MASTER_PASSPHRASE) as session:
        session.update_credential(record_id, _credential(title="Current"))

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute(
            "UPDATE credentials SET record_version = ?, nonce = ?, ciphertext = ? "
            "WHERE record_id = ?",
            (*old_row, bytes.fromhex(record_id)),
        )

    with pytest.raises(VaultIntegrityError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_manifest_ciphertext_tampering_is_detected(tmp_path: Path) -> None:

    vault_path = tmp_path / "manifest-tamper.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        ciphertext = bytearray(
            connection.execute("SELECT ciphertext FROM vault_manifest").fetchone()[0]
        )

        ciphertext[0] ^= 1
        connection.execute("UPDATE vault_manifest SET ciphertext = ?", (bytes(ciphertext),))

    with pytest.raises(VaultIntegrityError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_create_never_overwrites_an_existing_file(tmp_path: Path) -> None:

    vault_path = tmp_path / "existing.vault.sqlite3"
    vault_path.write_bytes(b"keep me")

    with pytest.raises(VaultAlreadyExistsError):
        create_vault(
            vault_path,
            FAKE_MASTER_PASSPHRASE,
            parameters=FAST_TEST_PARAMETERS,
        )

    assert vault_path.read_bytes() == b"keep me"


def test_non_vault_file_is_rejected(tmp_path: Path) -> None:

    path = tmp_path / "not-a-vault.sqlite3"
    path.write_text("not a SQLite vault", encoding="utf-8")
    with pytest.raises(VaultFormatError):
        open_vault(path, FAKE_MASTER_PASSPHRASE)


def test_missing_vault_is_rejected(tmp_path: Path) -> None:

    with pytest.raises(VaultNotFoundError):
        open_vault(tmp_path / "missing.vault.sqlite3", FAKE_MASTER_PASSPHRASE)


def test_missing_parent_folder_is_rejected(tmp_path: Path) -> None:

    with pytest.raises(VaultStorageError):
        create_vault(
            tmp_path / "missing" / "vault.sqlite3",
            FAKE_MASTER_PASSPHRASE,
            parameters=FAST_TEST_PARAMETERS,
        )


def test_invalid_parameter_object_is_rejected_before_file_creation(tmp_path: Path) -> None:

    vault_path = tmp_path / "bad-parameters.vault.sqlite3"
    with pytest.raises(VaultStorageError):
        create_vault(
            vault_path,
            FAKE_MASTER_PASSPHRASE,
            parameters=object(),  # type: ignore[arg-type]
        )

    assert not vault_path.exists()


@pytest.mark.parametrize("record_id", ["short", "z" * 32])
def test_invalid_record_id_is_rejected(unlocked_vault: VaultSession, record_id: str) -> None:

    with pytest.raises(RecordNotFoundError):
        unlocked_vault.get_credential(record_id)


def test_missing_record_update_and_delete_are_rejected(unlocked_vault: VaultSession) -> None:

    missing_id = "0" * 32
    with pytest.raises(RecordNotFoundError):
        unlocked_vault.update_credential(missing_id, _credential())
    with pytest.raises(RecordNotFoundError):
        unlocked_vault.delete_credential(missing_id)


def test_wrong_data_object_is_rejected(unlocked_vault: VaultSession) -> None:

    with pytest.raises(CredentialValidationError):
        unlocked_vault.add_credential(object())  # type: ignore[arg-type]
    with pytest.raises(CredentialValidationError):
        unlocked_vault.update_credential("0" * 32, object())  # type: ignore[arg-type]


def test_closed_session_cannot_be_reentered(unlocked_vault: VaultSession) -> None:

    unlocked_vault.close()
    with pytest.raises(VaultClosedError):
        with unlocked_vault:
            pass


@pytest.mark.parametrize(
    ("pragma", "value"),
    [
        ("application_id", 0),
        ("user_version", 99),
    ],
)
def test_database_identity_tampering_is_rejected(
    tmp_path: Path,
    pragma: str,
    value: int,
) -> None:

    vault_path = tmp_path / f"tampered-{pragma}.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass
    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute(f"PRAGMA {pragma} = {value}")  # noqa: S608

    with pytest.raises(VaultFormatError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_unexpected_schema_object_is_rejected(tmp_path: Path) -> None:

    vault_path = tmp_path / "extra-table.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass
    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute("CREATE TABLE attacker_added(value TEXT)")

    with pytest.raises(VaultFormatError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_missing_header_is_rejected(tmp_path: Path) -> None:

    vault_path = tmp_path / "missing-header.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass
    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute("DELETE FROM vault_header")

    with pytest.raises(VaultFormatError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_unsafe_header_kdf_parameters_are_rejected(tmp_path: Path) -> None:

    vault_path = tmp_path / "unsafe-header.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass

    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute("UPDATE vault_header SET argon2_memory_kib = 1")

    with pytest.raises(VaultFormatError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_missing_manifest_is_rejected(tmp_path: Path) -> None:

    vault_path = tmp_path / "missing-manifest.vault.sqlite3"
    with create_vault(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ):
        pass
    with closing(sqlite3.connect(vault_path)) as connection, connection:
        connection.execute("DELETE FROM vault_manifest")

    with pytest.raises(VaultIntegrityError):
        open_vault(vault_path, FAKE_MASTER_PASSPHRASE)


def test_closed_session_rejects_operations(unlocked_vault: VaultSession) -> None:

    unlocked_vault.close()
    with pytest.raises(VaultClosedError):
        unlocked_vault.list_credentials()


def test_new_vault_enforces_passphrase_policy(tmp_path: Path) -> None:

    with pytest.raises(PassphrasePolicyError):
        create_vault(
            tmp_path / "weak.vault.sqlite3",
            "passwordpassword",
            parameters=FAST_TEST_PARAMETERS,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"title": ""},
        {"title": "   "},
        {"password": ""},
    ],
)
def test_invalid_credentials_are_rejected(changes: dict[str, str]) -> None:

    values = {
        "title": "Example",
        "website": "",
        "username": "",
        "password": FAKE_PASSWORD,
        "notes": "",
    }

    values.update(changes)
    with pytest.raises(CredentialValidationError):
        CredentialData(**values)
