"""Encryption helpers; the Broker owns the live vault keys."""

from dataclasses import dataclass
from secrets import token_bytes

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from password_manager.core.exceptions import AuthenticationError, InvalidCryptographicInput
from password_manager.core.passphrases import (
    MAX_MASTER_PASSPHRASE_BYTES,
    normalize_master_passphrase,
)

AES_256_KEY_BYTES = 32
ARGON2_SALT_BYTES = 16
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
VAULT_ID_BYTES = 16
MAX_PASSPHRASE_BYTES = MAX_MASTER_PASSPHRASE_BYTES

MIN_ARGON2_MEMORY_KIB = 19 * 1024
MAX_ARGON2_MEMORY_KIB = 1024 * 1024
MIN_ARGON2_TIME_COST = 2
MAX_ARGON2_TIME_COST = 10
MAX_ARGON2_PARALLELISM = 4

_VAULT_KEY_WRAP_DOMAIN = b"password-manager-v2\x00vault-key-wrap\x00v1\x00"
_VAULT_SUBKEY_DOMAIN = b"password-manager-v2\x00vault-subkey\x00v1\x00"
_AUTHENTICATION_FAILURE_MESSAGE = "Encrypted data could not be authenticated."


def _require_plain_integer(name: str, value: int) -> None:

    if type(value) is not int:  # Deliberately reject bool, which is an int subclass.
        raise InvalidCryptographicInput(f"{name} must be an integer.")


def _require_bytes(name: str, value: bytes) -> None:

    if not isinstance(value, bytes):
        raise InvalidCryptographicInput(f"{name} must be bytes.")


def _require_exact_length(name: str, value: bytes, expected: int) -> None:
    _require_bytes(name, value)

    if len(value) != expected:
        raise InvalidCryptographicInput(f"{name} must be exactly {expected} bytes.")


@dataclass(frozen=True, slots=True)
class Argon2idParameters:
    """Stored, bounded Argon2id settings for deriving a 256-bit wrapping key."""

    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024
    parallelism: int = 1
    hash_length: int = AES_256_KEY_BYTES
    version: int = ARGON2_VERSION

    def __post_init__(self) -> None:
        for name in ("time_cost", "memory_cost_kib", "parallelism", "hash_length", "version"):
            _require_plain_integer(name, getattr(self, name))

        if not MIN_ARGON2_TIME_COST <= self.time_cost <= MAX_ARGON2_TIME_COST:
            raise InvalidCryptographicInput(
                f"time_cost must be between {MIN_ARGON2_TIME_COST} and {MAX_ARGON2_TIME_COST}."
            )

        if not MIN_ARGON2_MEMORY_KIB <= self.memory_cost_kib <= MAX_ARGON2_MEMORY_KIB:
            raise InvalidCryptographicInput(
                "memory_cost_kib is outside the accepted security and availability bounds."
            )

        if not 1 <= self.parallelism <= MAX_ARGON2_PARALLELISM:
            raise InvalidCryptographicInput(
                f"parallelism must be between 1 and {MAX_ARGON2_PARALLELISM}."
            )
        if self.hash_length != AES_256_KEY_BYTES:
            raise InvalidCryptographicInput("hash_length must be 32 bytes for AES-256.")

        if self.version != ARGON2_VERSION:
            raise InvalidCryptographicInput("Only Argon2 version 19 is supported.")


DEFAULT_ARGON2ID_PARAMETERS = Argon2idParameters()


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """AES-GCM nonce and ciphertext with its 128-bit tag appended."""

    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        _require_exact_length("nonce", self.nonce, AES_GCM_NONCE_BYTES)
        _require_bytes("ciphertext", self.ciphertext)

        if len(self.ciphertext) < AES_GCM_TAG_BYTES:
            raise InvalidCryptographicInput("ciphertext is too short to contain an AES-GCM tag.")


def generate_argon2_salt() -> bytes:

    return token_bytes(ARGON2_SALT_BYTES)


def generate_vault_id() -> bytes:

    return token_bytes(VAULT_ID_BYTES)


def generate_vault_key() -> bytes:

    return AESGCM.generate_key(bit_length=256)


def derive_vault_subkey(vault_key: bytes, vault_id: bytes, purpose: bytes) -> bytes:

    _require_exact_length("vault_key", vault_key, AES_256_KEY_BYTES)
    _require_exact_length("vault_id", vault_id, VAULT_ID_BYTES)
    _require_bytes("purpose", purpose)

    if not purpose or len(purpose) > 64:
        raise InvalidCryptographicInput("purpose must contain between 1 and 64 bytes.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_256_KEY_BYTES,
        salt=vault_id,
        info=_VAULT_SUBKEY_DOMAIN + purpose,
    ).derive(vault_key)


def derive_wrapping_key(
    master_passphrase: str,
    salt: bytes,
    parameters: Argon2idParameters = DEFAULT_ARGON2ID_PARAMETERS,
) -> bytes:
    """Preserve spaces and case; normalise Unicode to NFC before deriving the key."""

    if not isinstance(master_passphrase, str):
        raise InvalidCryptographicInput("master_passphrase must be text.")
    normalized_passphrase = normalize_master_passphrase(master_passphrase)

    if not normalized_passphrase:
        raise InvalidCryptographicInput("master_passphrase must not be empty.")
    _require_exact_length("salt", salt, ARGON2_SALT_BYTES)

    if not isinstance(parameters, Argon2idParameters):
        raise InvalidCryptographicInput("parameters must be Argon2idParameters.")

    try:
        passphrase_bytes = normalized_passphrase.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise InvalidCryptographicInput("master_passphrase contains invalid Unicode.") from error

    if len(passphrase_bytes) > MAX_PASSPHRASE_BYTES:
        raise InvalidCryptographicInput(
            f"master_passphrase must encode to at most {MAX_PASSPHRASE_BYTES} bytes."
        )

    return hash_secret_raw(
        secret=passphrase_bytes,
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_cost_kib,
        parallelism=parameters.parallelism,
        hash_len=parameters.hash_length,
        type=Type.ID,
        version=parameters.version,
    )


def encrypt_authenticated(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes,
) -> EncryptedPayload:

    _require_bytes("plaintext", plaintext)
    _require_exact_length("key", key, AES_256_KEY_BYTES)
    _require_bytes("associated_data", associated_data)

    if not associated_data:
        raise InvalidCryptographicInput("associated_data must identify the encrypted purpose.")

    nonce = token_bytes(AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return EncryptedPayload(nonce=nonce, ciphertext=ciphertext)


def decrypt_authenticated(
    encrypted: EncryptedPayload,
    key: bytes,
    associated_data: bytes,
) -> bytes:
    """Return the same authentication error for a wrong key or modified data."""

    if not isinstance(encrypted, EncryptedPayload):
        raise InvalidCryptographicInput("encrypted must be an EncryptedPayload.")

    _require_exact_length("key", key, AES_256_KEY_BYTES)
    _require_bytes("associated_data", associated_data)

    if not associated_data:
        raise InvalidCryptographicInput("associated_data must identify the encrypted purpose.")

    try:
        return AESGCM(key).decrypt(
            encrypted.nonce,
            encrypted.ciphertext,
            associated_data,
        )

    except InvalidTag:
        raise AuthenticationError(_AUTHENTICATION_FAILURE_MESSAGE) from None


def _vault_key_wrap_aad(vault_id: bytes) -> bytes:
    _require_exact_length("vault_id", vault_id, VAULT_ID_BYTES)
    return _VAULT_KEY_WRAP_DOMAIN + vault_id


def wrap_vault_key(
    vault_key: bytes,
    wrapping_key: bytes,
    vault_id: bytes,
) -> EncryptedPayload:

    _require_exact_length("vault_key", vault_key, AES_256_KEY_BYTES)
    return encrypt_authenticated(
        plaintext=vault_key,
        key=wrapping_key,
        associated_data=_vault_key_wrap_aad(vault_id),
    )


def unwrap_vault_key(
    encrypted_vault_key: EncryptedPayload,
    wrapping_key: bytes,
    vault_id: bytes,
) -> bytes:

    vault_key = decrypt_authenticated(
        encrypted=encrypted_vault_key,
        key=wrapping_key,
        associated_data=_vault_key_wrap_aad(vault_id),
    )

    if len(vault_key) != AES_256_KEY_BYTES:
        raise AuthenticationError(_AUTHENTICATION_FAILURE_MESSAGE)
    return vault_key
