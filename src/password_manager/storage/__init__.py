"""Encrypted vault storage used by the Broker."""

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
from password_manager.storage.vault import (
    VaultSession,
    convert_vault,
    create_vault,
    open_vault,
    restore_vault_backup,
)

__all__ = [
    "RecordNotFoundError",
    "VaultAlreadyExistsError",
    "VaultClosedError",
    "VaultFormatError",
    "VaultIntegrityError",
    "VaultNotFoundError",
    "VaultSession",
    "VaultStorageError",
    "VaultUnlockError",
    "create_vault",
    "convert_vault",
    "open_vault",
    "restore_vault_backup",
]
