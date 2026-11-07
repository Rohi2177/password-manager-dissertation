"""Expected vault and record errors."""


class VaultStorageError(Exception):
    """Base class for local vault and record-storage failures."""


class VaultAlreadyExistsError(VaultStorageError):
    """Raised rather than overwriting an existing file."""


class VaultNotFoundError(VaultStorageError):
    """Raised when the selected vault file does not exist."""


class VaultFormatError(VaultStorageError):
    """Raised when a file is not a supported vault database."""


class VaultUnlockError(VaultStorageError):
    """Generic public failure for an incorrect master passphrase."""


class VaultIntegrityError(VaultStorageError):
    """Raised when authenticated vault state is missing or inconsistent."""


class VaultClosedError(VaultStorageError):
    """Raised when an operation is attempted after closing a session."""


class RecordNotFoundError(VaultStorageError):
    """Raised when an opaque credential ID is not present."""
