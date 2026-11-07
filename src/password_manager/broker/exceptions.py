"""Errors that the interface can handle safely."""


class BrokerError(Exception):
    """Base class for Broker failures safe to handle at an IPC boundary."""


class BrokerCancelledError(BrokerError):
    """Raised when the user cancels a trusted Broker-owned dialog."""


class BrokerProtocolError(BrokerError):
    """Raised when an IPC message does not match the strict protocol."""


class BrokerDeniedError(BrokerError):
    """Generic denial for expired, replayed, altered, or unapproved requests."""


class BrokerLockedError(BrokerError):
    """Raised when a request requires an unlocked Broker session."""


class BrokerTransportError(BrokerError):
    """Raised when the authenticated local transport cannot be used safely."""
