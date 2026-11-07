"""Use one authentication error for incorrect keys or modified data."""


class CryptographicError(Exception):
    """Base class for expected cryptographic failures."""


class InvalidCryptographicInput(CryptographicError, ValueError):
    """Raised before encryption when a caller supplies malformed input."""


class AuthenticationError(CryptographicError):
    """Raised when encrypted data cannot be authenticated and decrypted."""
