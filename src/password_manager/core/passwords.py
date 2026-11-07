"""Generate passwords using the operating system's random source."""

from __future__ import annotations

import secrets
import string

MIN_GENERATED_PASSWORD_LENGTH = 12
MAX_GENERATED_PASSWORD_LENGTH = 128
DEFAULT_GENERATED_PASSWORD_LENGTH = 20
SAFE_SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"


def _secure_shuffle(characters: list[str]) -> None:
    for index in range(len(characters) - 1, 0, -1):
        selected = secrets.randbelow(index + 1)
        characters[index], characters[selected] = characters[selected], characters[index]


def generate_password(
    length: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:

    if (
        type(length) is not int
        or not MIN_GENERATED_PASSWORD_LENGTH <= length <= MAX_GENERATED_PASSWORD_LENGTH
    ):
        raise ValueError("Generated password length is outside the accepted range.")
    groups: list[str] = []

    if lowercase:
        groups.append(string.ascii_lowercase)

    if uppercase:
        groups.append(string.ascii_uppercase)

    if digits:
        groups.append(string.digits)

    if symbols:
        groups.append(SAFE_SYMBOLS)

    if not groups:
        raise ValueError("At least one password character group must be enabled.")

    if length < len(groups):
        raise ValueError("Password length is too short for the enabled character groups.")

    alphabet = "".join(groups)
    characters = [secrets.choice(group) for group in groups]
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(groups)))
    _secure_shuffle(characters)
    return "".join(characters)
