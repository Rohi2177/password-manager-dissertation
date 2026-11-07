"""Security-property tests for the vault cryptographic boundary."""

import pytest

from password_manager.core.crypto import (
    AES_256_KEY_BYTES,
    AES_GCM_NONCE_BYTES,
    ARGON2_SALT_BYTES,
    DEFAULT_ARGON2ID_PARAMETERS,
    MIN_ARGON2_MEMORY_KIB,
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

FAKE_TEST_PASSPHRASE = "Demo-only passphrase; never use this for a real vault!"  # noqa: S105
WRONG_FAKE_PASSPHRASE = "A different demo-only passphrase"  # noqa: S105
FAST_TEST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


@pytest.fixture(scope="module")
def wrapping_keys() -> tuple[bytes, bytes]:

    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    correct_key = derive_wrapping_key(FAKE_TEST_PASSPHRASE, salt, FAST_TEST_PARAMETERS)
    wrong_key = derive_wrapping_key(WRONG_FAKE_PASSPHRASE, salt, FAST_TEST_PARAMETERS)
    return correct_key, wrong_key


def test_default_argon2id_profile_preserves_cost_settings() -> None:

    assert DEFAULT_ARGON2ID_PARAMETERS.time_cost == 3
    assert DEFAULT_ARGON2ID_PARAMETERS.memory_cost_kib == 64 * 1024
    assert DEFAULT_ARGON2ID_PARAMETERS.parallelism == 1
    assert DEFAULT_ARGON2ID_PARAMETERS.hash_length == AES_256_KEY_BYTES


def test_default_argon2id_profile_derives_a_256_bit_key() -> None:

    salt = bytes.fromhex("102132435465768798a9bacbdcedfe0f")

    key = derive_wrapping_key(FAKE_TEST_PASSPHRASE, salt)

    assert len(key) == AES_256_KEY_BYTES


def test_random_material_has_required_lengths_and_is_fresh() -> None:

    first_salt = generate_argon2_salt()
    second_salt = generate_argon2_salt()
    first_vault_id = generate_vault_id()
    second_vault_id = generate_vault_id()
    first_key = generate_vault_key()
    second_key = generate_vault_key()

    assert len(first_salt) == ARGON2_SALT_BYTES
    assert len(first_vault_id) == 16
    assert len(first_key) == AES_256_KEY_BYTES
    assert first_salt != second_salt
    assert first_vault_id != second_vault_id
    assert first_key != second_key


def test_vault_subkeys_are_purpose_and_vault_bound() -> None:
    vault_key = generate_vault_key()
    first_vault_id = generate_vault_id()
    second_vault_id = generate_vault_id()

    record_key = derive_vault_subkey(vault_key, first_vault_id, b"record-key")
    repeated_record_key = derive_vault_subkey(vault_key, first_vault_id, b"record-key")
    manifest_key = derive_vault_subkey(vault_key, first_vault_id, b"manifest-key")
    other_vault_key = derive_vault_subkey(vault_key, second_vault_id, b"record-key")

    assert record_key == repeated_record_key
    assert record_key != manifest_key
    assert record_key != other_vault_key
    assert len(record_key) == AES_256_KEY_BYTES


@pytest.mark.parametrize("purpose", [b"", b"x" * 65])
def test_vault_subkey_rejects_invalid_purposes(purpose: bytes) -> None:

    with pytest.raises(InvalidCryptographicInput):
        derive_vault_subkey(generate_vault_key(), generate_vault_id(), purpose)


def test_argon2id_is_deterministic_and_salt_separates_keys() -> None:

    first_salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    second_salt = bytes.fromhex("ffeeddccbbaa99887766554433221100")

    first_key = derive_wrapping_key(
        FAKE_TEST_PASSPHRASE,
        first_salt,
        FAST_TEST_PARAMETERS,
    )

    repeated_key = derive_wrapping_key(
        FAKE_TEST_PASSPHRASE,
        first_salt,
        FAST_TEST_PARAMETERS,
    )

    separated_key = derive_wrapping_key(
        FAKE_TEST_PASSPHRASE,
        second_salt,
        FAST_TEST_PARAMETERS,
    )

    assert first_key == repeated_key
    assert first_key != separated_key
    assert len(first_key) == AES_256_KEY_BYTES


def test_vault_key_wrap_round_trip(wrapping_keys: tuple[bytes, bytes]) -> None:

    correct_key, _ = wrapping_keys
    vault_id = generate_vault_id()
    vault_key = generate_vault_key()

    encrypted = wrap_vault_key(vault_key, correct_key, vault_id)

    assert len(encrypted.nonce) == AES_GCM_NONCE_BYTES
    assert encrypted.ciphertext != vault_key
    assert unwrap_vault_key(encrypted, correct_key, vault_id) == vault_key


def test_same_vault_key_gets_a_fresh_nonce(wrapping_keys: tuple[bytes, bytes]) -> None:

    correct_key, _ = wrapping_keys
    vault_id = generate_vault_id()
    vault_key = generate_vault_key()

    first = wrap_vault_key(vault_key, correct_key, vault_id)
    second = wrap_vault_key(vault_key, correct_key, vault_id)

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_wrong_passphrase_key_has_generic_failure(wrapping_keys: tuple[bytes, bytes]) -> None:

    correct_key, wrong_key = wrapping_keys
    vault_id = generate_vault_id()
    encrypted = wrap_vault_key(generate_vault_key(), correct_key, vault_id)

    with pytest.raises(AuthenticationError, match="could not be authenticated"):
        unwrap_vault_key(encrypted, wrong_key, vault_id)


def test_tampering_has_generic_failure(wrapping_keys: tuple[bytes, bytes]) -> None:

    correct_key, _ = wrapping_keys
    vault_id = generate_vault_id()
    encrypted = wrap_vault_key(generate_vault_key(), correct_key, vault_id)
    changed_ciphertext = bytearray(encrypted.ciphertext)
    changed_ciphertext[-1] ^= 1
    tampered = EncryptedPayload(
        nonce=encrypted.nonce,
        ciphertext=bytes(changed_ciphertext),
    )

    with pytest.raises(AuthenticationError, match="could not be authenticated"):
        unwrap_vault_key(tampered, correct_key, vault_id)


def test_vault_id_is_authenticated(wrapping_keys: tuple[bytes, bytes]) -> None:

    correct_key, _ = wrapping_keys
    original_vault_id = generate_vault_id()
    different_vault_id = generate_vault_id()
    encrypted = wrap_vault_key(generate_vault_key(), correct_key, original_vault_id)

    with pytest.raises(AuthenticationError, match="could not be authenticated"):
        unwrap_vault_key(encrypted, correct_key, different_vault_id)


@pytest.mark.parametrize(
    ("passphrase", "salt"),
    [
        ("", b"0" * ARGON2_SALT_BYTES),
        (FAKE_TEST_PASSPHRASE, b"too-short"),
    ],
)
def test_invalid_derivation_input_is_rejected(passphrase: str, salt: bytes) -> None:

    with pytest.raises(InvalidCryptographicInput):
        derive_wrapping_key(passphrase, salt, FAST_TEST_PARAMETERS)


@pytest.mark.parametrize(
    "changes",
    [
        {"time_cost": True},
        {"time_cost": 1},
        {"time_cost": 11},
        {"memory_cost_kib": MIN_ARGON2_MEMORY_KIB - 1},
        {"memory_cost_kib": 1024 * 1024 + 1},
        {"parallelism": 0},
        {"parallelism": 5},
        {"hash_length": 16},
        {"version": 18},
    ],
)
def test_unsafe_or_unbounded_argon2_parameters_are_rejected(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "time_cost": 3,
        "memory_cost_kib": 64 * 1024,
        "parallelism": 1,
        "hash_length": AES_256_KEY_BYTES,
        "version": 19,
    }

    values.update(changes)

    with pytest.raises(InvalidCryptographicInput):
        Argon2idParameters(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "passphrase",
    [
        123,
        "\ud800",
        "a" * 1025,
    ],
)
def test_malformed_passphrase_values_are_rejected(passphrase: object) -> None:

    with pytest.raises(InvalidCryptographicInput):
        derive_wrapping_key(  # type: ignore[arg-type]
            passphrase,
            b"0" * ARGON2_SALT_BYTES,
            FAST_TEST_PARAMETERS,
        )


@pytest.mark.parametrize(
    "encrypted",
    [
        (b"short", b"0" * 16),
        (b"0" * AES_GCM_NONCE_BYTES, b"short"),
    ],
)
def test_malformed_encrypted_payload_is_rejected(encrypted: tuple[bytes, bytes]) -> None:
    nonce, ciphertext = encrypted

    with pytest.raises(InvalidCryptographicInput):
        EncryptedPayload(nonce=nonce, ciphertext=ciphertext)


def test_authenticated_encryption_requires_a_256_bit_key_and_purpose() -> None:

    with pytest.raises(InvalidCryptographicInput):
        encrypt_authenticated(b"fake data", b"short-key", b"test-purpose")

    with pytest.raises(InvalidCryptographicInput):
        encrypt_authenticated(b"fake data", generate_vault_key(), b"")


def test_authenticated_decryption_rejects_wrong_public_input_types() -> None:
    with pytest.raises(InvalidCryptographicInput):
        decrypt_authenticated(  # type: ignore[arg-type]
            b"not-an-encrypted-payload",
            generate_vault_key(),
            b"test-purpose",
        )
