"""Encrypted SQLite storage. Unlocked sessions belong in the Broker."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from secrets import token_bytes
from typing import Any, Self

from password_manager.core.crypto import (
    AES_GCM_NONCE_BYTES,
    ARGON2_SALT_BYTES,
    DEFAULT_ARGON2ID_PARAMETERS,
    VAULT_ID_BYTES,
    Argon2idParameters,
    EncryptedPayload,
    decrypt_authenticated,
    derive_vault_subkey,
    derive_wrapping_key,
    encrypt_authenticated,
    generate_argon2_salt,
    generate_vault_id,
    generate_vault_key,
    unwrap_vault_key,
    wrap_vault_key,
)
from password_manager.core.exceptions import AuthenticationError, InvalidCryptographicInput
from password_manager.core.models import CredentialData, CredentialRecord, CredentialValidationError
from password_manager.core.passphrases import PassphrasePolicyError, validate_new_master_passphrase
from password_manager.security.file_permissions import harden_private_file
from password_manager.storage.exceptions import (
    RecordNotFoundError,
    VaultAlreadyExistsError,
    VaultClosedError,
    VaultFormatError,
    VaultIntegrityError,
    VaultNotFoundError,
    VaultStorageError,
    VaultUnlockError,
)

SQLITE_APPLICATION_ID = 0x504D5632  # ASCII-like marker: PMV2
LEGACY_VAULT_FORMAT_VERSION = 1
VAULT_FORMAT_VERSION = 3
RECORD_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 1


RECORD_ID_BYTES = 16
MAX_RECORDS = 10_000
MAX_RECORD_PAYLOAD_BYTES = 64 * 1024
MAX_MANIFEST_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_VAULT_FILE_BYTES = 512 * 1024 * 1024
MAX_SQLITE_INTEGER = (1 << 63) - 1
MAX_SEARCH_QUERY_CHARACTERS = 200


_RECORD_DOMAIN = b"password-manager-v2\x00credential-record\x00v1\x00"
_MANIFEST_DOMAIN = b"password-manager-v2\x00vault-manifest\x00v1\x00"
_RECORD_KEY_PURPOSE = b"credential-record-key"
_MANIFEST_KEY_PURPOSE = b"vault-manifest-key"


_SCHEMA_SQL = """
CREATE TABLE vault_header (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version INTEGER NOT NULL CHECK (format_version = 3),
    vault_id BLOB NOT NULL CHECK (length(vault_id) = 16),
    kdf_name TEXT NOT NULL CHECK (kdf_name = 'argon2id'),
    argon2_version INTEGER NOT NULL,
    argon2_memory_kib INTEGER NOT NULL,
    argon2_time_cost INTEGER NOT NULL,
    argon2_parallelism INTEGER NOT NULL,
    salt BLOB NOT NULL CHECK (length(salt) = 16),
    wrapped_key_nonce BLOB NOT NULL CHECK (length(wrapped_key_nonce) = 12),
    wrapped_key_ciphertext BLOB NOT NULL CHECK (length(wrapped_key_ciphertext) = 48)
) STRICT;


CREATE TABLE vault_manifest (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    nonce BLOB NOT NULL CHECK (length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16)
) STRICT;


CREATE TABLE credentials (
    record_id BLOB PRIMARY KEY CHECK (length(record_id) = 16),
    record_version INTEGER NOT NULL CHECK (record_version >= 1),
    nonce BLOB NOT NULL CHECK (length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16)
) STRICT;
"""


_SCHEMA_OBJECTS = {
    ("table", "credentials"),
    ("table", "vault_header"),
    ("table", "vault_manifest"),
}


_SCHEMA_COLUMNS = {
    "vault_header": (
        "singleton",
        "format_version",
        "vault_id",
        "kdf_name",
        "argon2_version",
        "argon2_memory_kib",
        "argon2_time_cost",
        "argon2_parallelism",
        "salt",
        "wrapped_key_nonce",
        "wrapped_key_ciphertext",
    ),
    "vault_manifest": ("singleton", "revision", "nonce", "ciphertext"),
    "credentials": ("record_id", "record_version", "nonce", "ciphertext"),
}


@dataclass(frozen=True, slots=True)
class _VaultHeader:
    vault_id: bytes
    parameters: Argon2idParameters
    salt: bytes
    encrypted_vault_key: EncryptedPayload


@dataclass(frozen=True, slots=True)
class _ManifestEntry:
    version: int
    ciphertext_digest: str


@dataclass(frozen=True, slots=True)
class _Manifest:
    revision: int
    records: dict[str, _ManifestEntry]


def _expect_integer(name: str, value: object, *, minimum: int, maximum: int) -> int:

    if type(value) is not int or not minimum <= value <= maximum:
        raise VaultFormatError(f"Invalid {name} in vault format.")
    return value


def _expect_bytes(name: str, value: object, *, exact_length: int | None = None) -> bytes:

    if not isinstance(value, bytes):
        raise VaultFormatError(f"Invalid {name} in vault format.")

    if exact_length is not None and len(value) != exact_length:
        raise VaultFormatError(f"Invalid {name} length in vault format.")
    return value


def _expect_text(name: str, value: object) -> str:

    if not isinstance(value, str):
        raise VaultFormatError(f"Invalid {name} in vault format.")
    return value


def _normalize_path(path: str | Path) -> Path:

    if not isinstance(path, (str, Path)):
        raise VaultStorageError("The vault path must be text or a Path.")

    try:
        return Path(path).expanduser().absolute()

    except (OSError, RuntimeError, ValueError) as error:
        raise VaultStorageError("The vault path is invalid.") from error


def _configure_connection(connection: sqlite3.Connection) -> None:

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA secure_delete = ON")
    journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()

    if journal_mode is None or str(journal_mode[0]).lower() != "delete":
        raise VaultStorageError("SQLite could not enable the required journal mode.")
    connection.execute("PRAGMA synchronous = FULL")


def _connect_new(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=5.0)


def _connect_existing(path: Path) -> sqlite3.Connection:

    uri = path.as_uri() + "?mode=rw"
    return sqlite3.connect(uri, timeout=5.0, uri=True)


def _reserve_new_vault_file(path: Path) -> None:

    if not path.parent.is_dir():
        raise VaultStorageError("The vault's parent folder does not exist.")

    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)

    except FileExistsError as error:
        raise VaultAlreadyExistsError("The selected vault file already exists.") from error

    except OSError as error:
        raise VaultStorageError("The vault file could not be created.") from error

    else:
        os.close(descriptor)

    try:
        harden_private_file(path)
    except OSError as error:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise VaultStorageError("The vault file could not be made private.") from error


def _verify_database_identity(connection: sqlite3.Connection) -> int:

    application_row = connection.execute("PRAGMA application_id").fetchone()
    version_row = connection.execute("PRAGMA user_version").fetchone()
    if application_row is None or application_row[0] != SQLITE_APPLICATION_ID:
        raise VaultFormatError("The selected file is not a Password Manager vault.")
    if version_row is None or version_row[0] not in {
        LEGACY_VAULT_FORMAT_VERSION,
        VAULT_FORMAT_VERSION,
    }:
        raise VaultFormatError("This vault format needs conversion before it can be opened.")
    format_version = int(version_row[0])

    object_rows = connection.execute(
        "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    actual_objects = {(row["type"], row["name"]) for row in object_rows}

    if actual_objects != _SCHEMA_OBJECTS:
        raise VaultFormatError("The vault database schema is unexpected.")

    _verify_core_columns(connection)

    integrity_rows = connection.execute("PRAGMA quick_check").fetchall()
    if len(integrity_rows) != 1 or integrity_rows[0][0] != "ok":
        raise VaultFormatError("SQLite reported vault database corruption.")
    return format_version


def _verify_core_columns(connection: sqlite3.Connection) -> None:
    for table, expected_columns in _SCHEMA_COLUMNS.items():
        # Table names come only from the fixed schema above.
        rows = connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
        if tuple(row["name"] for row in rows) != expected_columns:
            raise VaultFormatError("The vault database columns are unexpected.")


def _load_header(connection: sqlite3.Connection, format_version: int) -> _VaultHeader:
    rows = connection.execute("SELECT * FROM vault_header").fetchall()

    if len(rows) != 1:
        raise VaultFormatError("The vault header is missing or duplicated.")
    row = rows[0]

    if row["singleton"] != 1 or row["format_version"] != format_version:
        raise VaultFormatError("The vault header version is invalid.")
    if _expect_text("kdf_name", row["kdf_name"]) != "argon2id":
        raise VaultFormatError("The vault uses an unsupported key derivation function.")

    try:
        parameters = Argon2idParameters(
            version=_expect_integer(
                "argon2_version",
                row["argon2_version"],
                minimum=0,
                maximum=MAX_SQLITE_INTEGER,
            ),
            memory_cost_kib=_expect_integer(
                "argon2_memory_kib",
                row["argon2_memory_kib"],
                minimum=0,
                maximum=MAX_SQLITE_INTEGER,
            ),
            time_cost=_expect_integer(
                "argon2_time_cost",
                row["argon2_time_cost"],
                minimum=0,
                maximum=MAX_SQLITE_INTEGER,
            ),
            parallelism=_expect_integer(
                "argon2_parallelism",
                row["argon2_parallelism"],
                minimum=0,
                maximum=MAX_SQLITE_INTEGER,
            ),
        )

        encrypted_vault_key = EncryptedPayload(
            nonce=_expect_bytes(
                "wrapped_key_nonce",
                row["wrapped_key_nonce"],
                exact_length=AES_GCM_NONCE_BYTES,
            ),
            ciphertext=_expect_bytes(
                "wrapped_key_ciphertext",
                row["wrapped_key_ciphertext"],
                exact_length=48,
            ),
        )

    except InvalidCryptographicInput as error:
        raise VaultFormatError("The vault header contains unsafe parameters.") from error

    return _VaultHeader(
        vault_id=_expect_bytes("vault_id", row["vault_id"], exact_length=VAULT_ID_BYTES),
        parameters=parameters,
        salt=_expect_bytes("salt", row["salt"], exact_length=ARGON2_SALT_BYTES),
        encrypted_vault_key=encrypted_vault_key,
    )


def _record_aad(vault_id: bytes, record_id: bytes, version: int) -> bytes:

    return _RECORD_DOMAIN + vault_id + record_id + struct.pack(">Q", version)


def _manifest_aad(vault_id: bytes, revision: int) -> bytes:

    return _MANIFEST_DOMAIN + vault_id + struct.pack(">Q", revision)


def _ciphertext_digest(encrypted: EncryptedPayload) -> str:
    return hashlib.sha256(encrypted.nonce + encrypted.ciphertext).hexdigest()


def _serialize_credential(data: CredentialData) -> bytes:
    payload = {
        "notes": data.notes,
        "password": data.password,
        "schema_version": RECORD_SCHEMA_VERSION,
        "title": data.title,
        "username": data.username,
        "website": data.website,
    }

    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    if len(serialized) > MAX_RECORD_PAYLOAD_BYTES:
        raise CredentialValidationError("The encrypted credential payload is too large.")
    return serialized


def _deserialize_credential(payload: bytes) -> CredentialData:

    if len(payload) > MAX_RECORD_PAYLOAD_BYTES:
        raise VaultIntegrityError("An encrypted credential payload is unreasonably large.")

    try:
        value: Any = json.loads(payload.decode("utf-8", errors="strict"))

    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VaultIntegrityError("An encrypted credential payload is malformed.") from error

    expected_keys = {"schema_version", "title", "website", "username", "password", "notes"}

    if not isinstance(value, dict) or set(value) != expected_keys:
        raise VaultIntegrityError("An encrypted credential payload has an unexpected schema.")

    if value.get("schema_version") != RECORD_SCHEMA_VERSION:
        raise VaultIntegrityError("An encrypted credential payload version is unsupported.")

    try:
        return CredentialData(
            title=value["title"],
            website=value["website"],
            username=value["username"],
            password=value["password"],
            notes=value["notes"],
        )

    except (CredentialValidationError, TypeError) as error:
        raise VaultIntegrityError("An encrypted credential payload is invalid.") from error


def _serialize_manifest(manifest: _Manifest) -> bytes:
    records = [
        [record_id, entry.version, entry.ciphertext_digest]
        for record_id, entry in sorted(manifest.records.items())
    ]

    serialized = json.dumps(
        {
            "records": records,
            "revision": manifest.revision,
            "schema_version": MANIFEST_SCHEMA_VERSION,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")

    if len(serialized) > MAX_MANIFEST_PAYLOAD_BYTES:
        raise VaultStorageError("The authenticated vault manifest is too large.")
    return serialized


def _is_lower_hex(value: str, expected_length: int) -> bool:

    if len(value) != expected_length or value != value.lower():
        return False

    try:
        bytes.fromhex(value)

    except ValueError:
        return False
    return True


def _deserialize_manifest(payload: bytes) -> _Manifest:

    if len(payload) > MAX_MANIFEST_PAYLOAD_BYTES:
        raise VaultIntegrityError("The authenticated vault manifest is too large.")
    try:
        value: Any = json.loads(payload.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VaultIntegrityError("The authenticated vault manifest is malformed.") from error

    if not isinstance(value, dict) or set(value) != {"schema_version", "revision", "records"}:
        raise VaultIntegrityError("The authenticated vault manifest schema is invalid.")

    if value.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise VaultIntegrityError("The authenticated vault manifest version is unsupported.")
    revision = value.get("revision")
    records_value = value.get("records")

    if type(revision) is not int or not 0 <= revision <= MAX_SQLITE_INTEGER:
        raise VaultIntegrityError("The authenticated vault revision is invalid.")

    if not isinstance(records_value, list) or len(records_value) > MAX_RECORDS:
        raise VaultIntegrityError("The authenticated vault record list is invalid.")

    records: dict[str, _ManifestEntry] = {}
    for item in records_value:
        if not isinstance(item, list) or len(item) != 3:
            raise VaultIntegrityError("An authenticated manifest entry is malformed.")
        record_id, version, digest = item

        if not isinstance(record_id, str) or not _is_lower_hex(record_id, RECORD_ID_BYTES * 2):
            raise VaultIntegrityError("An authenticated record ID is invalid.")

        if type(version) is not int or not 1 <= version <= MAX_SQLITE_INTEGER:
            raise VaultIntegrityError("An authenticated record version is invalid.")

        if not isinstance(digest, str) or not _is_lower_hex(digest, 64):
            raise VaultIntegrityError("An authenticated record digest is invalid.")

        if record_id in records:
            raise VaultIntegrityError("The authenticated manifest contains a duplicate record.")
        records[record_id] = _ManifestEntry(version=version, ciphertext_digest=digest)
    return _Manifest(revision=revision, records=records)


def _database_record_snapshot(connection: sqlite3.Connection) -> dict[str, _ManifestEntry]:
    rows = connection.execute(
        "SELECT record_id, record_version, nonce, ciphertext FROM credentials ORDER BY record_id"
    ).fetchall()

    if len(rows) > MAX_RECORDS:
        raise VaultIntegrityError("The vault contains too many credential records.")

    records: dict[str, _ManifestEntry] = {}
    for row in rows:
        record_id = _expect_bytes("record_id", row["record_id"], exact_length=RECORD_ID_BYTES)
        version = _expect_integer(
            "record_version",
            row["record_version"],
            minimum=1,
            maximum=MAX_SQLITE_INTEGER,
        )

        try:
            encrypted = EncryptedPayload(
                nonce=_expect_bytes(
                    "record nonce",
                    row["nonce"],
                    exact_length=AES_GCM_NONCE_BYTES,
                ),
                ciphertext=_expect_bytes("record ciphertext", row["ciphertext"]),
            )

        except InvalidCryptographicInput as error:
            raise VaultIntegrityError("A stored credential envelope is malformed.") from error
        records[record_id.hex()] = _ManifestEntry(
            version=version,
            ciphertext_digest=_ciphertext_digest(encrypted),
        )

    return records


def _load_and_verify_manifest(
    connection: sqlite3.Connection,
    manifest_key: bytes,
    vault_id: bytes,
) -> _Manifest:

    try:
        rows = connection.execute(
            "SELECT revision, nonce, ciphertext FROM vault_manifest"
        ).fetchall()
        if len(rows) != 1:
            raise VaultIntegrityError("The authenticated vault manifest is missing or duplicated.")
        row = rows[0]
        revision = _expect_integer(
            "manifest revision",
            row["revision"],
            minimum=0,
            maximum=MAX_SQLITE_INTEGER,
        )

        encrypted = EncryptedPayload(
            nonce=_expect_bytes(
                "manifest nonce",
                row["nonce"],
                exact_length=AES_GCM_NONCE_BYTES,
            ),
            ciphertext=_expect_bytes("manifest ciphertext", row["ciphertext"]),
        )

        payload = decrypt_authenticated(
            encrypted=encrypted,
            key=manifest_key,
            associated_data=_manifest_aad(vault_id, revision),
        )

    except (AuthenticationError, InvalidCryptographicInput, VaultFormatError) as error:
        raise VaultIntegrityError(
            "The authenticated vault manifest could not be verified."
        ) from error

    manifest = _deserialize_manifest(payload)

    if manifest.revision != revision:
        raise VaultIntegrityError("The vault manifest revision does not match its envelope.")

    try:
        database_records = _database_record_snapshot(connection)

    except VaultFormatError as error:
        raise VaultIntegrityError("A stored credential envelope is malformed.") from error

    if manifest.records != database_records:
        raise VaultIntegrityError("The credential table does not match its authenticated manifest.")
    return manifest


def _store_manifest(
    connection: sqlite3.Connection,
    manifest_key: bytes,
    vault_id: bytes,
    manifest: _Manifest,
) -> None:
    encrypted = encrypt_authenticated(
        plaintext=_serialize_manifest(manifest),
        key=manifest_key,
        associated_data=_manifest_aad(vault_id, manifest.revision),
    )

    cursor = connection.execute(
        "UPDATE vault_manifest SET revision = ?, nonce = ?, ciphertext = ? WHERE singleton = 1",
        (manifest.revision, encrypted.nonce, encrypted.ciphertext),
    )
    if cursor.rowcount != 1:
        raise VaultIntegrityError("The authenticated vault manifest could not be updated.")


def _decode_record_id(record_id: str) -> bytes:

    if not isinstance(record_id, str) or len(record_id) != RECORD_ID_BYTES * 2:
        raise RecordNotFoundError("The credential record ID is invalid.")
    try:
        decoded = bytes.fromhex(record_id)
    except ValueError as error:
        raise RecordNotFoundError("The credential record ID is invalid.") from error

    if len(decoded) != RECORD_ID_BYTES:
        raise RecordNotFoundError("The credential record ID is invalid.")
    return decoded


def _next_manifest(manifest: _Manifest, records: dict[str, _ManifestEntry]) -> _Manifest:

    if manifest.revision >= MAX_SQLITE_INTEGER:
        raise VaultStorageError("The vault revision limit has been reached.")
    return _Manifest(revision=manifest.revision + 1, records=records)


class VaultSession:
    """An unlocked vault session intended to live only inside the Broker."""

    def __init__(
        self,
        *,
        path: Path,
        connection: sqlite3.Connection,
        vault_id: bytes,
        vault_key: bytes,
    ) -> None:

        self._path = path
        self._connection: sqlite3.Connection | None = connection
        self._vault_id = vault_id
        self._vault_key = vault_key
        self._record_key = derive_vault_subkey(vault_key, vault_id, _RECORD_KEY_PURPOSE)
        self._manifest_key = derive_vault_subkey(vault_key, vault_id, _MANIFEST_KEY_PURPOSE)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def vault_id(self) -> str:
        return self._vault_id.hex()

    @property
    def is_open(self) -> bool:

        return self._connection is not None

    def __enter__(self) -> Self:

        if not self.is_open:
            raise VaultClosedError("The vault session is closed.")
        return self

    def __exit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        self.close()

    def _state(self) -> tuple[sqlite3.Connection, bytes, bytes]:
        if self._connection is None:
            raise VaultClosedError("The vault session is closed.")
        return self._connection, self._record_key, self._manifest_key

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        self._vault_key = b""
        self._record_key = b""
        self._manifest_key = b""
        if connection is not None:
            connection.close()

    def verify_integrity(self) -> int:
        """Check the manifest and authenticate every encrypted record."""

        connection, record_key, manifest_key = self._state()

        try:
            connection.execute("BEGIN")
            manifest = _load_and_verify_manifest(connection, manifest_key, self._vault_id)
            rows = connection.execute(
                "SELECT record_id, record_version, nonce, ciphertext "
                "FROM credentials ORDER BY record_id"
            ).fetchall()
            for row in rows:
                self._decrypt_row(row, record_key)
            connection.commit()
            return len(manifest.records)
        except VaultStorageError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise VaultStorageError("SQLite could not verify the vault.") from error

    def _decrypt_row(self, row: sqlite3.Row, record_key: bytes) -> CredentialRecord:
        record_id = _expect_bytes("record_id", row["record_id"], exact_length=RECORD_ID_BYTES)
        version = _expect_integer(
            "record_version",
            row["record_version"],
            minimum=1,
            maximum=MAX_SQLITE_INTEGER,
        )

        try:
            encrypted = EncryptedPayload(
                nonce=_expect_bytes(
                    "record nonce",
                    row["nonce"],
                    exact_length=AES_GCM_NONCE_BYTES,
                ),
                ciphertext=_expect_bytes("record ciphertext", row["ciphertext"]),
            )

            plaintext = decrypt_authenticated(
                encrypted=encrypted,
                key=record_key,
                associated_data=_record_aad(self._vault_id, record_id, version),
            )

        except (AuthenticationError, InvalidCryptographicInput, VaultFormatError) as error:
            raise VaultIntegrityError("A credential record could not be authenticated.") from error
        return CredentialRecord(
            record_id=record_id.hex(),
            version=version,
            data=_deserialize_credential(plaintext),
        )

    def add_credential(self, data: CredentialData) -> str:

        if not isinstance(data, CredentialData):
            raise CredentialValidationError("data must be CredentialData.")
        connection, record_key, manifest_key = self._state()

        try:
            connection.execute("BEGIN IMMEDIATE")
            manifest = _load_and_verify_manifest(connection, manifest_key, self._vault_id)
            if len(manifest.records) >= MAX_RECORDS:
                raise VaultStorageError("The record limit has been reached.")

            record_id = token_bytes(RECORD_ID_BYTES)
            while record_id.hex() in manifest.records:
                record_id = token_bytes(RECORD_ID_BYTES)
            version = 1
            encrypted = encrypt_authenticated(
                plaintext=_serialize_credential(data),
                key=record_key,
                associated_data=_record_aad(self._vault_id, record_id, version),
            )

            connection.execute(
                "INSERT INTO credentials(record_id, record_version, nonce, ciphertext) "
                "VALUES (?, ?, ?, ?)",
                (record_id, version, encrypted.nonce, encrypted.ciphertext),
            )
            records = dict(manifest.records)
            records[record_id.hex()] = _ManifestEntry(
                version=version,
                ciphertext_digest=_ciphertext_digest(encrypted),
            )

            _store_manifest(
                connection,
                manifest_key,
                self._vault_id,
                _next_manifest(manifest, records),
            )
            connection.commit()
            return record_id.hex()
        except (VaultStorageError, CredentialValidationError):
            connection.rollback()
            raise
        except (sqlite3.Error, InvalidCryptographicInput) as error:
            connection.rollback()
            raise VaultStorageError("The credential could not be added.") from error

    def get_credential(self, record_id: str) -> CredentialRecord:
        decoded_id = _decode_record_id(record_id)
        connection, record_key, manifest_key = self._state()

        try:
            connection.execute("BEGIN")
            manifest = _load_and_verify_manifest(connection, manifest_key, self._vault_id)

            if decoded_id.hex() not in manifest.records:
                raise RecordNotFoundError("The credential record does not exist.")
            row = connection.execute(
                "SELECT record_id, record_version, nonce, ciphertext "
                "FROM credentials WHERE record_id = ?",
                (decoded_id,),
            ).fetchone()

            if row is None:
                raise VaultIntegrityError("A manifested credential record is missing.")
            record = self._decrypt_row(row, record_key)
            connection.commit()
            return record
        except VaultStorageError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise VaultStorageError("The credential could not be read.") from error

    def list_credentials(self) -> list[CredentialRecord]:
        connection, record_key, manifest_key = self._state()

        try:
            connection.execute("BEGIN")
            _load_and_verify_manifest(connection, manifest_key, self._vault_id)
            rows = connection.execute(
                "SELECT record_id, record_version, nonce, ciphertext "
                "FROM credentials ORDER BY record_id"
            ).fetchall()
            records = [self._decrypt_row(row, record_key) for row in rows]
            connection.commit()
            return records
        except VaultStorageError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise VaultStorageError("The credential list could not be read.") from error

    def search_credentials(self, query: str) -> list[CredentialRecord]:
        """Search inside the Broker without matching password fields."""

        if not isinstance(query, str):
            raise CredentialValidationError("The search query must be text.")

        if len(query) > MAX_SEARCH_QUERY_CHARACTERS:
            raise CredentialValidationError("The search query is too long.")
        normalized_query = unicodedata.normalize("NFC", query).strip().casefold()
        records = self.list_credentials()

        if not normalized_query:
            return records
        return [
            record
            for record in records
            if any(
                normalized_query in unicodedata.normalize("NFC", value).casefold()
                for value in (
                    record.data.title,
                    record.data.website,
                    record.data.username,
                    record.data.notes,
                )
            )
        ]

    def update_credential(self, record_id: str, data: CredentialData) -> CredentialRecord:
        if not isinstance(data, CredentialData):
            raise CredentialValidationError("data must be CredentialData.")
        decoded_id = _decode_record_id(record_id)
        connection, record_key, manifest_key = self._state()

        try:
            connection.execute("BEGIN IMMEDIATE")
            manifest = _load_and_verify_manifest(connection, manifest_key, self._vault_id)
            old_entry = manifest.records.get(decoded_id.hex())

            if old_entry is None:
                raise RecordNotFoundError("The credential record does not exist.")

            if old_entry.version >= MAX_SQLITE_INTEGER:
                raise VaultStorageError("The credential version limit has been reached.")

            new_version = old_entry.version + 1
            encrypted = encrypt_authenticated(
                plaintext=_serialize_credential(data),
                key=record_key,
                associated_data=_record_aad(self._vault_id, decoded_id, new_version),
            )
            cursor = connection.execute(
                "UPDATE credentials SET record_version = ?, nonce = ?, ciphertext = ? "
                "WHERE record_id = ?",
                (new_version, encrypted.nonce, encrypted.ciphertext, decoded_id),
            )

            if cursor.rowcount != 1:
                raise VaultIntegrityError("The credential record disappeared during update.")
            records = dict(manifest.records)
            records[decoded_id.hex()] = _ManifestEntry(
                version=new_version,
                ciphertext_digest=_ciphertext_digest(encrypted),
            )

            _store_manifest(
                connection,
                manifest_key,
                self._vault_id,
                _next_manifest(manifest, records),
            )

            connection.commit()
            return CredentialRecord(record_id=decoded_id.hex(), version=new_version, data=data)
        except (VaultStorageError, CredentialValidationError):
            connection.rollback()
            raise
        except (sqlite3.Error, InvalidCryptographicInput) as error:
            connection.rollback()
            raise VaultStorageError("The credential could not be updated.") from error

    def delete_credential(self, record_id: str) -> None:
        decoded_id = _decode_record_id(record_id)
        connection, _record_key, manifest_key = self._state()

        try:
            connection.execute("BEGIN IMMEDIATE")
            manifest = _load_and_verify_manifest(connection, manifest_key, self._vault_id)

            if decoded_id.hex() not in manifest.records:
                raise RecordNotFoundError("The credential record does not exist.")
            cursor = connection.execute(
                "DELETE FROM credentials WHERE record_id = ?",
                (decoded_id,),
            )

            if cursor.rowcount != 1:
                raise VaultIntegrityError("The credential record disappeared during deletion.")
            records = dict(manifest.records)
            del records[decoded_id.hex()]
            _store_manifest(
                connection,
                manifest_key,
                self._vault_id,
                _next_manifest(manifest, records),
            )

            connection.commit()
        except VaultStorageError:
            connection.rollback()
            raise
        except (sqlite3.Error, InvalidCryptographicInput) as error:
            connection.rollback()
            raise VaultStorageError("The credential could not be deleted.") from error

    def create_encrypted_backup(self, destination: str | Path) -> Path:
        """Copy and verify the encrypted database without overwriting a file."""

        source_connection, record_key, manifest_key = self._state()
        destination_path = _normalize_path(destination)
        _reserve_new_vault_file(destination_path)
        backup_connection: sqlite3.Connection | None = None
        try:
            backup_connection = _connect_new(destination_path)
            source_connection.backup(backup_connection)
            _configure_connection(backup_connection)
            _verify_database_identity(backup_connection)
            manifest = _load_and_verify_manifest(
                backup_connection,
                manifest_key,
                self._vault_id,
            )

            rows = backup_connection.execute(
                "SELECT record_id, record_version, nonce, ciphertext "
                "FROM credentials ORDER BY record_id"
            ).fetchall()
            for row in rows:
                self._decrypt_row(row, record_key)

            if len(rows) != len(manifest.records):
                raise VaultIntegrityError("The encrypted backup record count is inconsistent.")
            backup_connection.close()
            return destination_path

        except VaultStorageError:
            if backup_connection is not None:
                backup_connection.close()
            _remove_incomplete_new_vault(destination_path)
            raise
        except (OSError, sqlite3.Error) as error:
            if backup_connection is not None:
                backup_connection.close()
            _remove_incomplete_new_vault(destination_path)
            raise VaultStorageError("The encrypted backup could not be created.") from error


def _remove_incomplete_new_vault(path: Path) -> None:
    for candidate in (
        path,
        path.with_name(path.name + "-journal"),
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
    ):
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def create_vault(
    path: str | Path,
    master_passphrase: str,
    *,
    parameters: Argon2idParameters = DEFAULT_ARGON2ID_PARAMETERS,
) -> VaultSession:
    """Create a new encrypted vault without overwriting an existing file."""

    normalized_passphrase = validate_new_master_passphrase(master_passphrase)
    if not isinstance(parameters, Argon2idParameters):
        raise VaultStorageError("parameters must be safe Argon2idParameters.")
    vault_path = _normalize_path(path)
    _reserve_new_vault_file(vault_path)

    connection: sqlite3.Connection | None = None
    try:
        connection = _connect_new(vault_path)
        _configure_connection(connection)
        connection.executescript(_SCHEMA_SQL)
        connection.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {VAULT_FORMAT_VERSION}")

        vault_id = generate_vault_id()
        salt = generate_argon2_salt()
        vault_key = generate_vault_key()
        manifest_key = derive_vault_subkey(vault_key, vault_id, _MANIFEST_KEY_PURPOSE)
        wrapping_key = derive_wrapping_key(normalized_passphrase, salt, parameters)
        encrypted_vault_key = wrap_vault_key(vault_key, wrapping_key, vault_id)
        empty_manifest = _Manifest(revision=0, records={})
        encrypted_manifest = encrypt_authenticated(
            plaintext=_serialize_manifest(empty_manifest),
            key=manifest_key,
            associated_data=_manifest_aad(vault_id, empty_manifest.revision),
        )

        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO vault_header("
            "singleton, format_version, vault_id, kdf_name, argon2_version, "
            "argon2_memory_kib, argon2_time_cost, argon2_parallelism, salt, "
            "wrapped_key_nonce, wrapped_key_ciphertext"
            ") VALUES (1, ?, ?, 'argon2id', ?, ?, ?, ?, ?, ?, ?)",
            (
                VAULT_FORMAT_VERSION,
                vault_id,
                parameters.version,
                parameters.memory_cost_kib,
                parameters.time_cost,
                parameters.parallelism,
                salt,
                encrypted_vault_key.nonce,
                encrypted_vault_key.ciphertext,
            ),
        )

        connection.execute(
            "INSERT INTO vault_manifest(singleton, revision, nonce, ciphertext) "
            "VALUES (1, ?, ?, ?)",
            (empty_manifest.revision, encrypted_manifest.nonce, encrypted_manifest.ciphertext),
        )

        connection.commit()
        _verify_database_identity(connection)

        session = VaultSession(
            path=vault_path,
            connection=connection,
            vault_id=vault_id,
            vault_key=vault_key,
        )

        session.verify_integrity()
        return session
    except (PassphrasePolicyError, VaultStorageError, InvalidCryptographicInput):
        if connection is not None:
            connection.close()
        _remove_incomplete_new_vault(vault_path)
        raise
    except (OSError, sqlite3.Error) as error:
        if connection is not None:
            connection.close()
        _remove_incomplete_new_vault(vault_path)
        raise VaultStorageError("The encrypted vault could not be initialized.") from error
    except Exception:
        if connection is not None:
            connection.close()
        _remove_incomplete_new_vault(vault_path)
        raise


def open_vault(path: str | Path, master_passphrase: str) -> VaultSession:
    """Authenticate the manifest and every record before opening the vault."""

    vault_path = _normalize_path(path)

    if not vault_path.exists() or not vault_path.is_file():
        raise VaultNotFoundError("The selected vault file does not exist.")
    if vault_path.is_symlink():
        raise VaultFormatError("Symbolic-link vault paths are not accepted.")
    connection: sqlite3.Connection | None = None

    try:
        if vault_path.stat().st_size > MAX_VAULT_FILE_BYTES:
            raise VaultFormatError("The selected vault exceeds the size limit.")
        connection = _connect_existing(vault_path)
        _configure_connection(connection)
        format_version = _verify_database_identity(connection)
        header = _load_header(connection, format_version)

    except VaultStorageError:
        if connection is not None:
            connection.close()
        raise

    except (OSError, sqlite3.Error) as error:
        if connection is not None:
            connection.close()
        raise VaultFormatError("The selected file could not be read as a vault.") from error

    if connection is None:
        raise VaultFormatError("The selected vault could not be opened.")

    try:
        wrapping_key = derive_wrapping_key(
            master_passphrase,
            header.salt,
            header.parameters,
        )

        vault_key = unwrap_vault_key(
            header.encrypted_vault_key,
            wrapping_key,
            header.vault_id,
        )
    except (AuthenticationError, InvalidCryptographicInput):
        connection.close()
        raise VaultUnlockError("Unable to unlock the vault.") from None

    session = VaultSession(
        path=vault_path,
        connection=connection,
        vault_id=header.vault_id,
        vault_key=vault_key,
    )

    try:
        session.verify_integrity()
        harden_private_file(vault_path)
    except Exception:
        session.close()
        raise
    return session


def restore_vault_backup(
    backup_path: str | Path,
    destination: str | Path,
    master_passphrase: str,
) -> VaultSession:
    """Verify the backup before copying it to a new file."""

    with open_vault(backup_path, master_passphrase) as backup_session:
        restored_path = backup_session.create_encrypted_backup(destination)
    return open_vault(restored_path, master_passphrase)


def convert_vault(
    source: str | Path,
    destination: str | Path,
    master_passphrase: str,
) -> Path:
    """Copy authenticated older records to fresh keys; leave the source untouched."""

    source_path = _normalize_path(source)
    destination_path = _normalize_path(destination)

    if source_path.is_symlink():
        raise VaultFormatError("Symbolic-link vault paths are not accepted.")

    if not source_path.is_file():
        raise VaultNotFoundError("The selected vault file does not exist.")
    connection: sqlite3.Connection | None = None
    session: VaultSession | None = None
    created = False

    try:
        if source_path.stat().st_size > MAX_VAULT_FILE_BYTES:
            raise VaultFormatError("The selected vault exceeds the size limit.")
        connection = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        format_version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id != SQLITE_APPLICATION_ID or format_version not in {1, 2, 3}:
            raise VaultFormatError("The selected file is not a supported vault.")
        objects = {
            (row["type"], row["name"])
            for row in connection.execute(
                "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
            )
        }

        if not _SCHEMA_OBJECTS <= objects or any(kind != "table" for kind, _ in objects):
            raise VaultFormatError("The older vault database schema is unexpected.")
        _verify_core_columns(connection)

        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise VaultIntegrityError("The selected vault database is damaged.")
        header = _load_header(connection, format_version)

        try:
            wrapping_key = derive_wrapping_key(master_passphrase, header.salt, header.parameters)
            vault_key = unwrap_vault_key(
                header.encrypted_vault_key,
                wrapping_key,
                header.vault_id,
            )

        except (AuthenticationError, InvalidCryptographicInput):
            raise VaultUnlockError("Unable to unlock the vault.") from None

        session = VaultSession(
            path=source_path,
            connection=connection,
            vault_id=header.vault_id,
            vault_key=vault_key,
        )

        # Keep header, manifest and records in the same read-only snapshot.
        _, record_key, manifest_key = session._state()
        _load_and_verify_manifest(connection, manifest_key, header.vault_id)
        rows = connection.execute(
            "SELECT record_id, record_version, nonce, ciphertext "
            "FROM credentials ORDER BY record_id"
        )

        records = [session._decrypt_row(row, record_key) for row in rows]
        with create_vault(destination_path, master_passphrase) as converted:
            created = True
            for record in records:
                converted.add_credential(record.data)
            converted.verify_integrity()
        return destination_path
    except BaseException:
        if created:
            _remove_incomplete_new_vault(destination_path)
        raise
    finally:
        if session is not None:
            session.close()

        elif connection is not None:
            connection.close()
