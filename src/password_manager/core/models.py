"""Validated account fields stored together as encrypted data."""

from dataclasses import dataclass

MAX_TITLE_CHARACTERS = 200
MAX_WEBSITE_CHARACTERS = 2048
MAX_USERNAME_CHARACTERS = 512
MAX_PASSWORD_CHARACTERS = 4096
MAX_NOTES_CHARACTERS = 32_768


class CredentialValidationError(ValueError):
    """Raised when credential data cannot safely enter the encrypted format."""


def _validate_text(
    name: str,
    value: str,
    *,
    maximum: int,
    allow_empty: bool,
) -> None:

    if not isinstance(value, str):
        raise CredentialValidationError(f"{name} must be text.")

    if not allow_empty and not value:
        raise CredentialValidationError(f"{name} must not be empty.")

    if len(value) > maximum:
        raise CredentialValidationError(f"{name} exceeds its maximum supported length.")


@dataclass(frozen=True, slots=True)
class CredentialData:
    """One credential payload; every field is encrypted as one AEAD message."""

    title: str
    website: str
    username: str
    password: str
    notes: str = ""

    def __post_init__(self) -> None:
        _validate_text("title", self.title, maximum=MAX_TITLE_CHARACTERS, allow_empty=False)

        if not self.title.strip():
            raise CredentialValidationError("title cannot contain only whitespace.")
        _validate_text(
            "website",
            self.website,
            maximum=MAX_WEBSITE_CHARACTERS,
            allow_empty=True,
        )

        _validate_text(
            "username",
            self.username,
            maximum=MAX_USERNAME_CHARACTERS,
            allow_empty=True,
        )

        _validate_text(
            "password",
            self.password,
            maximum=MAX_PASSWORD_CHARACTERS,
            allow_empty=False,
        )

        _validate_text("notes", self.notes, maximum=MAX_NOTES_CHARACTERS, allow_empty=True)


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    """A decrypted credential together with its opaque ID and revision."""

    record_id: str
    version: int
    data: CredentialData
