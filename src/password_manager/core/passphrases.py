"""Check new passphrases locally and normalise Unicode consistently."""

from unicodedata import normalize

MIN_MASTER_PASSPHRASE_CHARACTERS = 15
MAX_MASTER_PASSPHRASE_BYTES = 1024

_BLOCKED_NORMALIZED_PASSPHRASES = frozenset(
    {
        "123456789012345",
        "correcthorsebatterystaple",
        "dissertationpassword",
        "letmeinletmeinletmein",
        "password manager",
        "password123456",
        "passwordpassword",
        "qwertyuiopasdfgh",
        "welcome123456789",
    }
)


class PassphrasePolicyError(ValueError):
    """Raised when a new master passphrase violates the onboarding policy."""


def normalize_master_passphrase(master_passphrase: str) -> str:

    if not isinstance(master_passphrase, str):
        raise PassphrasePolicyError("The master passphrase must be text.")
    return normalize("NFC", master_passphrase)


def validate_new_master_passphrase(master_passphrase: str) -> str:

    normalized = normalize_master_passphrase(master_passphrase)

    if len(normalized) < MIN_MASTER_PASSPHRASE_CHARACTERS:
        raise PassphrasePolicyError(
            "The master passphrase must contain at least "
            f"{MIN_MASTER_PASSPHRASE_CHARACTERS} characters."
        )

    if not normalized.strip():
        raise PassphrasePolicyError("The master passphrase cannot contain only whitespace.")

    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise PassphrasePolicyError("The master passphrase contains invalid Unicode.") from error

    if len(encoded) > MAX_MASTER_PASSPHRASE_BYTES:
        raise PassphrasePolicyError("The master passphrase is longer than the supported maximum.")

    blocklist_candidate = normalized.strip().casefold()
    if blocklist_candidate in _BLOCKED_NORMALIZED_PASSPHRASES:
        raise PassphrasePolicyError(
            "That master passphrase is commonly used or expected; choose a different phrase."
        )
    return normalized
