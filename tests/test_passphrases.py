"""Tests for master-passphrase normalization and new-vault policy."""

import pytest

from password_manager.core.crypto import (
    ARGON2_SALT_BYTES,
    MIN_ARGON2_MEMORY_KIB,
    Argon2idParameters,
    derive_wrapping_key,
)
from password_manager.core.passphrases import (
    PassphrasePolicyError,
    normalize_master_passphrase,
    validate_new_master_passphrase,
)

FAST_TEST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


def test_new_passphrase_accepts_long_lowercase_words_and_spaces() -> None:

    passphrase = "four quiet river stones"  # noqa: S105
    assert validate_new_master_passphrase(passphrase) == passphrase


@pytest.mark.parametrize(
    "passphrase",
    [
        "too short",
        "               ",
        "passwordpassword",
        " correcthorsebatterystaple ",
    ],
)
def test_weak_new_master_passphrases_are_rejected(passphrase: str) -> None:

    with pytest.raises(PassphrasePolicyError):
        validate_new_master_passphrase(passphrase)


def test_unicode_is_normalized_to_nfc_before_derivation() -> None:

    composed = "Caf\u00e9 dissertation phrase"  # noqa: S105
    decomposed = "Cafe\u0301 dissertation phrase"  # noqa: S105
    salt = b"0" * ARGON2_SALT_BYTES

    assert normalize_master_passphrase(decomposed) == composed
    assert derive_wrapping_key(composed, salt, FAST_TEST_PARAMETERS) == derive_wrapping_key(
        decomposed,
        salt,
        FAST_TEST_PARAMETERS,
    )


def test_case_and_surrounding_spaces_remain_significant() -> None:

    salt = b"0" * ARGON2_SALT_BYTES
    plain = "Long demo phrase"  # noqa: S105

    plain_key = derive_wrapping_key(plain, salt, FAST_TEST_PARAMETERS)

    assert plain_key != derive_wrapping_key("long demo phrase", salt, FAST_TEST_PARAMETERS)
    assert plain_key != derive_wrapping_key(" Long demo phrase ", salt, FAST_TEST_PARAMETERS)


@pytest.mark.parametrize(
    "passphrase",
    [
        123,
        "\ud800" * 15,
        "a" * 1025,
    ],
)
def test_invalid_or_oversized_new_passphrase_is_rejected(passphrase: object) -> None:

    with pytest.raises(PassphrasePolicyError):
        validate_new_master_passphrase(passphrase)  # type: ignore[arg-type]
