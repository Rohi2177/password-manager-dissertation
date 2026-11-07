"""Old vaults must be authenticated before copying data into a fresh vault."""

import runpy
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest

import password_manager.storage.vault as storage
from password_manager.core.crypto import (
    MIN_ARGON2_MEMORY_KIB,
    Argon2idParameters,
    derive_wrapping_key,
    unwrap_vault_key,
)
from password_manager.core.models import CredentialData
from password_manager.storage import (
    VaultAlreadyExistsError,
    VaultFormatError,
    VaultIntegrityError,
    VaultSession,
    VaultUnlockError,
    convert_vault,
    create_vault,
    open_vault,
)

FAKE_PASSPHRASE = "violet amber quiet harbor meadow"  # noqa: S105
FAST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


def make_source(path: Path, format_version: int = 2) -> list[CredentialData]:

    records = [
        CredentialData("Mail 🔐", "https://example.invalid", "demo", "fake-password-1", "α notes"),
        CredentialData("Mail 🔐", "https://other.invalid", "demo2", "fake-password-2", "β notes"),
    ]

    with create_vault(path, FAKE_PASSPHRASE, parameters=FAST_PARAMETERS) as vault:
        for data in records:
            vault.add_credential(data)

    with closing(sqlite3.connect(path)) as connection, connection:
        connection.row_factory = sqlite3.Row
        header = connection.execute("SELECT * FROM vault_header").fetchone()
        values = list(header)
        values[1] = format_version
        connection.execute("DROP TABLE vault_header")
        header_sql = storage._SCHEMA_SQL.split("CREATE TABLE vault_manifest")[0]
        connection.executescript(
            header_sql.replace("format_version = 3", f"format_version = {format_version}")
        )
        connection.execute(
            "INSERT INTO vault_header VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values
        )

        connection.execute(f"PRAGMA user_version = {format_version}")

        if format_version == 2:
            connection.execute("CREATE TABLE obsolete_metadata(value BLOB)")
            connection.execute("INSERT INTO obsolete_metadata VALUES (?)", (b"discarded-marker",))
    return records


def read_key(path: Path) -> bytes:

    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        header = storage._load_header(connection, version)
    wrapping_key = derive_wrapping_key(FAKE_PASSPHRASE, header.salt, header.parameters)
    return unwrap_vault_key(header.encrypted_vault_key, wrapping_key, header.vault_id)


@pytest.mark.parametrize("format_version", [1, 2, 3])
def test_conversion_preserves_data_rekeys_and_leaves_source_unchanged(
    tmp_path: Path,
    format_version: int,
) -> None:

    source = tmp_path / "older.pmvault"
    destination = tmp_path / "converted.pmvault"
    records = make_source(source, format_version)
    original_bytes = source.read_bytes()
    original_key = read_key(source)

    assert convert_vault(source, destination, FAKE_PASSPHRASE) == destination

    assert source.read_bytes() == original_bytes
    assert read_key(destination) != original_key
    assert b"discarded-marker" not in destination.read_bytes()

    for data in records:
        assert data.password.encode() not in destination.read_bytes()
        assert data.notes.encode() not in destination.read_bytes()

    with open_vault(destination, FAKE_PASSPHRASE) as vault:
        assert {record.data for record in vault.list_credentials()} == set(records)
        assert vault.verify_integrity() == 2

    with closing(sqlite3.connect(destination)) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
        ).fetchall()

        assert tables == [("credentials",), ("vault_header",), ("vault_manifest",)]
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_wrong_passphrase_cannot_convert(tmp_path: Path) -> None:

    source = tmp_path / "older.pmvault"
    destination = tmp_path / "converted.pmvault"
    make_source(source)
    original_bytes = source.read_bytes()

    with pytest.raises(VaultUnlockError):
        convert_vault(source, destination, "incorrect fake passphrase")
    assert source.read_bytes() == original_bytes
    assert not destination.exists()


def test_modified_ciphertext_cannot_be_converted(tmp_path: Path) -> None:

    source = tmp_path / "older.pmvault"
    destination = tmp_path / "converted.pmvault"
    make_source(source)

    with closing(sqlite3.connect(source)) as connection, connection:
        connection.execute("UPDATE credentials SET ciphertext = zeroblob(length(ciphertext))")

    with pytest.raises(VaultIntegrityError):
        convert_vault(source, destination, FAKE_PASSPHRASE)
    assert not destination.exists()


def test_conversion_never_overwrites_an_existing_file(tmp_path: Path) -> None:

    source = tmp_path / "older.pmvault"
    destination = tmp_path / "keep.txt"
    make_source(source)
    destination.write_text("keep this file")

    with pytest.raises(VaultAlreadyExistsError):
        convert_vault(source, destination, FAKE_PASSPHRASE)
    assert destination.read_text() == "keep this file"


def test_partial_conversion_is_removed_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    source = tmp_path / "older.pmvault"
    destination = tmp_path / "converted.pmvault"
    make_source(source)
    original_bytes = source.read_bytes()
    add_credential = VaultSession.add_credential
    calls = 0

    def fail_second_write(self: VaultSession, data: CredentialData) -> str:

        nonlocal calls
        calls += 1

        if calls == 2:
            raise OSError("Simulated disk write failure")
        return add_credential(self, data)

    monkeypatch.setattr(VaultSession, "add_credential", fail_second_write)
    with pytest.raises(OSError, match="Simulated"):
        convert_vault(source, destination, FAKE_PASSPHRASE)
    assert not destination.exists()
    assert source.read_bytes() == original_bytes


def test_normal_open_rejects_older_format_and_unexpected_columns(tmp_path: Path) -> None:

    source = tmp_path / "older.pmvault"
    make_source(source)

    with pytest.raises(VaultFormatError, match="conversion"):
        open_vault(source, FAKE_PASSPHRASE)
    clean = tmp_path / "clean.pmvault"

    with create_vault(clean, FAKE_PASSPHRASE, parameters=FAST_PARAMETERS):
        pass

    with closing(sqlite3.connect(clean)) as connection, connection:
        connection.execute("ALTER TABLE vault_header ADD COLUMN unexpected BLOB")

    with pytest.raises(VaultFormatError, match="columns"):
        open_vault(clean, FAKE_PASSPHRASE)


def test_original_three_table_format_still_opens(tmp_path: Path) -> None:

    source = tmp_path / "original.pmvault"
    records = make_source(source, 1)
    with open_vault(source, FAKE_PASSPHRASE) as vault:
        assert {record.data for record in vault.list_credentials()} == set(records)


@pytest.mark.parametrize("correct_phrase", [True, False])
def test_conversion_command_reports_success_or_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    correct_phrase: bool,
) -> None:

    source = tmp_path / "older.pmvault"
    destination = tmp_path / "converted.pmvault"
    records = make_source(source)
    original_bytes = source.read_bytes()
    phrase = FAKE_PASSPHRASE if correct_phrase else "incorrect fake passphrase"
    script = Path(__file__).resolve().parents[1] / "scripts" / "convert_vault.py"
    monkeypatch.setattr(sys, "argv", [str(script), str(source), str(destination)])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: phrase)

    with pytest.raises(SystemExit) as result:
        runpy.run_path(str(script), run_name="__main__")

    output = capsys.readouterr().out
    assert source.read_bytes() == original_bytes
    assert phrase not in output

    if correct_phrase:
        assert result.value.code == 0
        assert "Conversion complete" in output
        with open_vault(destination, FAKE_PASSPHRASE) as vault:
            assert {record.data for record in vault.list_credentials()} == set(records)

    else:
        assert result.value.code == 1
        assert "Conversion failed" in output
        assert not destination.exists()


def test_conversion_command_help(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:

    script = Path(__file__).resolve().parents[1] / "scripts" / "convert_vault.py"
    monkeypatch.setattr(sys, "argv", [str(script), "--help"])
    with pytest.raises(SystemExit) as result:
        runpy.run_path(str(script), run_name="__main__")
    assert result.value.code == 0
    assert "destination" in capsys.readouterr().out
