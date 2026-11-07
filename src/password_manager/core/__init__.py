"""Encryption, record validation and password generation."""

from password_manager.core.crypto import (
    DEFAULT_ARGON2ID_PARAMETERS,
    Argon2idParameters,
    EncryptedPayload,
    derive_vault_subkey,
    derive_wrapping_key,
    generate_argon2_salt,
    generate_vault_id,
    generate_vault_key,
    unwrap_vault_key,
    wrap_vault_key,
)
from password_manager.core.exceptions import (
    AuthenticationError,
    CryptographicError,
    InvalidCryptographicInput,
)
from password_manager.core.models import (
    CredentialData,
    CredentialRecord,
    CredentialValidationError,
)
from password_manager.core.passphrases import (
    PassphrasePolicyError,
    normalize_master_passphrase,
    validate_new_master_passphrase,
)
from password_manager.core.passwords import generate_password

__all__ = [
    "DEFAULT_ARGON2ID_PARAMETERS",
    "Argon2idParameters",
    "AuthenticationError",
    "CryptographicError",
    "CredentialData",
    "CredentialRecord",
    "CredentialValidationError",
    "EncryptedPayload",
    "InvalidCryptographicInput",
    "PassphrasePolicyError",
    "derive_wrapping_key",
    "derive_vault_subkey",
    "generate_argon2_salt",
    "generate_vault_id",
    "generate_vault_key",
    "generate_password",
    "normalize_master_passphrase",
    "unwrap_vault_key",
    "validate_new_master_passphrase",
    "wrap_vault_key",
]
