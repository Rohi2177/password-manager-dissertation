"""Focused parser tests for authenticated storage payloads."""

import json

import pytest

import password_manager.storage.vault as vault_module
from password_manager.storage import VaultIntegrityError


def _json_bytes(value: object) -> bytes:

    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"not-json",
        b"[]",
        _json_bytes({"schema_version": 1}),
        _json_bytes(
            {
                "notes": "",
                "password": "fake",
                "schema_version": 2,
                "title": "Demo",
                "username": "",
                "website": "",
            }
        ),
        _json_bytes(
            {
                "notes": "",
                "password": 123,
                "schema_version": 1,
                "title": "Demo",
                "username": "",
                "website": "",
            }
        ),
    ],
)
def test_malformed_decrypted_credentials_are_rejected(payload: bytes) -> None:

    with pytest.raises(VaultIntegrityError):
        vault_module._deserialize_credential(payload)


def test_oversized_decrypted_credential_is_rejected() -> None:
    with pytest.raises(VaultIntegrityError):
        vault_module._deserialize_credential(b"x" * (vault_module.MAX_RECORD_PAYLOAD_BYTES + 1))


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"schema_version": 1},
        {"schema_version": 2, "revision": 0, "records": []},
        {"schema_version": 1, "revision": -1, "records": []},
        {"schema_version": 1, "revision": True, "records": []},
        {"schema_version": 1, "revision": 0, "records": {}},
        {"schema_version": 1, "revision": 0, "records": [["short", 1, "0" * 64]]},
        {"schema_version": 1, "revision": 0, "records": [["A" * 32, 1, "0" * 64]]},
        {"schema_version": 1, "revision": 0, "records": [["0" * 32, 0, "0" * 64]]},
        {"schema_version": 1, "revision": 0, "records": [["0" * 32, True, "0" * 64]]},
        {"schema_version": 1, "revision": 0, "records": [["0" * 32, 1, "bad"]]},
        {"schema_version": 1, "revision": 0, "records": [["0" * 32, 1, "A" * 64]]},
        {
            "schema_version": 1,
            "revision": 0,
            "records": [["0" * 32, 1, "0" * 64], ["0" * 32, 1, "0" * 64]],
        },
    ],
)
def test_malformed_decrypted_manifests_are_rejected(value: object) -> None:

    with pytest.raises(VaultIntegrityError):
        vault_module._deserialize_manifest(_json_bytes(value))


@pytest.mark.parametrize("payload", [b"\xff", b"not-json"])
def test_non_json_manifest_is_rejected(payload: bytes) -> None:
    with pytest.raises(VaultIntegrityError):
        vault_module._deserialize_manifest(payload)


def test_oversized_manifest_is_rejected() -> None:

    with pytest.raises(VaultIntegrityError):
        vault_module._deserialize_manifest(b"x" * (vault_module.MAX_MANIFEST_PAYLOAD_BYTES + 1))


def test_manifest_serializer_enforces_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:

    manifest = vault_module._Manifest(revision=0, records={})
    monkeypatch.setattr(vault_module, "MAX_MANIFEST_PAYLOAD_BYTES", 1)
    with pytest.raises(vault_module.VaultStorageError):
        vault_module._serialize_manifest(manifest)
