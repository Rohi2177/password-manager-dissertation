"""Tests for the vault cryptographically secure password generator."""

import string

import pytest

from password_manager.core.passwords import (
    DEFAULT_GENERATED_PASSWORD_LENGTH,
    MAX_GENERATED_PASSWORD_LENGTH,
    MIN_GENERATED_PASSWORD_LENGTH,
    SAFE_SYMBOLS,
    generate_password,
)


def test_default_password_has_expected_length_and_every_character_group() -> None:

    generated = generate_password()

    assert len(generated) == DEFAULT_GENERATED_PASSWORD_LENGTH
    assert any(character in string.ascii_lowercase for character in generated)
    assert any(character in string.ascii_uppercase for character in generated)
    assert any(character in string.digits for character in generated)
    assert any(character in SAFE_SYMBOLS for character in generated)


@pytest.mark.parametrize(
    "options",
    [
        {"uppercase": False, "digits": False, "symbols": False},
        {"lowercase": False, "digits": False, "symbols": False},
        {"lowercase": False, "uppercase": False, "symbols": False},
        {"lowercase": False, "uppercase": False, "digits": False},
    ],
)
def test_single_selected_group_is_respected(options: dict[str, bool]) -> None:

    generated = generate_password(MIN_GENERATED_PASSWORD_LENGTH, **options)
    enabled = ""

    if options.get("lowercase", True):
        enabled += string.ascii_lowercase
    if options.get("uppercase", True):
        enabled += string.ascii_uppercase

    if options.get("digits", True):
        enabled += string.digits

    if options.get("symbols", True):
        enabled += SAFE_SYMBOLS

    assert len(generated) == MIN_GENERATED_PASSWORD_LENGTH
    assert all(character in enabled for character in generated)


@pytest.mark.parametrize(
    "length",
    [True, MIN_GENERATED_PASSWORD_LENGTH - 1, MAX_GENERATED_PASSWORD_LENGTH + 1],
)
def test_invalid_password_lengths_are_rejected(length: object) -> None:

    with pytest.raises(ValueError, match="length"):
        generate_password(length)  # type: ignore[arg-type]


def test_at_least_one_character_group_is_required() -> None:

    with pytest.raises(ValueError, match="At least one"):
        generate_password(
            lowercase=False,
            uppercase=False,
            digits=False,
            symbols=False,
        )
