"""Handle vault requests inside the Broker process."""

from __future__ import annotations

import os
from multiprocessing.connection import Listener, _ConnectionBase
from pathlib import Path

from password_manager.broker.exceptions import BrokerError
from password_manager.broker.peer import verify_same_user_peer
from password_manager.broker.service import (
    BrokerService,
)
from password_manager.broker.transport import JsonChannel
from password_manager.security import UnlockThrottle
from password_manager.security.audit import SecurityAuditLog
from password_manager.storage import (
    VaultFormatError,
    VaultSession,
    VaultUnlockError,
    create_vault,
    open_vault,
    restore_vault_backup,
)

STARTUP_READY = b"ready"
STARTUP_FAILED = b"failed"
STARTUP_CANCELLED = b"cancelled"


def _send_startup_status(connection: _ConnectionBase[object, object], status: bytes) -> None:

    try:
        connection.send_bytes(status)
    except (BrokenPipeError, EOFError, OSError):
        pass


def _prepare_interactive_vault(
    vault_path: str,
    master_passphrase: str,
    *,
    create_new: bool,
    restore_destination: str | None,
) -> VaultSession:
    """Create, unlock or restore entirely inside the Broker."""

    if create_new and restore_destination is not None:
        raise ValueError("Create and restore modes are mutually exclusive.")

    if create_new:
        return create_vault(vault_path, master_passphrase)

    if restore_destination is not None:
        return restore_vault_backup(vault_path, restore_destination, master_passphrase)
    return open_vault(vault_path, master_passphrase)


def run_interactive_broker_server(
    vault_path: str,
    address: str,
    family: str,
    authkey: bytes,
    ready_connection: _ConnectionBase[object, object],
    create_new: bool,
    restore_destination: str | None = None,
) -> None:

    # These Qt imports intentionally occur only in the isolated child process.
    from password_manager.broker.trusted_dialogs import (
        BrokerDialogApprovalPolicy,
        broker_application,
        create_clipboard_guard,
        request_master_passphrase,
        show_trusted_error,
    )

    listener: Listener | None = None
    channel: JsonChannel | None = None
    service: BrokerService | None = None
    clipboard_guard = None

    try:
        audit: SecurityAuditLog | None = SecurityAuditLog("broker")
    except OSError:
        audit = None

    def audit_event(event: str) -> None:
        if audit is not None:
            try:
                audit.record(event)
            except OSError:
                pass

    startup_reported = False
    application = broker_application()
    throttle = UnlockThrottle()
    vault: VaultSession | None = None

    try:
        restoring = restore_destination is not None
        previous_error = ""
        while True:
            unlock_delay = 0 if create_new else throttle.remaining_seconds(vault_path)

            if unlock_delay:
                audit_event("unlock_throttled")
            master_passphrase = request_master_passphrase(
                Path(vault_path).name,
                create_new=create_new,
                restore_backup=restoring,
                previous_error=previous_error,
                unlock_delay_seconds=unlock_delay,
            )

            if master_passphrase is None:
                _send_startup_status(ready_connection, STARTUP_CANCELLED)
                startup_reported = True
                return

            try:
                vault = _prepare_interactive_vault(
                    vault_path,
                    master_passphrase,
                    create_new=create_new,
                    restore_destination=restore_destination,
                )

            except VaultFormatError:
                master_passphrase = ""
                show_trusted_error(
                    "This vault cannot be opened. Check that you selected a valid vault file. "
                    "Make sure the file was created by a compatible version of Password Manager."
                )

                _send_startup_status(ready_connection, STARTUP_FAILED)
                startup_reported = True
                return

            except VaultUnlockError:
                master_passphrase = ""
                throttle.record_failure(vault_path)
                audit_event("unlock_failed")
                previous_error = (
                    "The backup or vault could not be unlocked. "
                    "Check the passphrase and selected file."
                )

                continue
            except Exception:
                master_passphrase = ""
                if create_new or restoring:
                    show_trusted_error(
                        "The encrypted vault could not be created safely at the selected location."
                    )

                    _send_startup_status(ready_connection, STARTUP_FAILED)
                    startup_reported = True
                    return
                throttle.record_failure(vault_path)
                audit_event("unlock_failed")
                previous_error = (
                    "The vault could not be unlocked. Check the passphrase and selected file."
                )

                continue
            master_passphrase = ""
            throttle.reset(vault_path)
            audit_event(
                "vault_created"
                if create_new
                else "backup_restored"
                if restoring
                else "unlock_succeeded"
            )

            break

        clipboard_guard = create_clipboard_guard(audit_event)
        service = BrokerService(
            vault,
            approval_policy=BrokerDialogApprovalPolicy(audit_event),
            clipboard_writer=clipboard_guard.copy,
        )

        listener = Listener(address, family=family, backlog=1, authkey=authkey)
        if family == "AF_UNIX":
            os.chmod(address, 0o600)
        _send_startup_status(ready_connection, STARTUP_READY)
        startup_reported = True
        ready_connection.close()

        connection = listener.accept()

        try:
            verify_same_user_peer(connection, peer_role="client")
            channel = JsonChannel(connection)

        except Exception:
            connection.close()
            raise

        while not service.is_locked:
            message = channel.receive_message()
            response = service.handle_message(message)
            channel.send_message(response)
            application.processEvents()

    except (BrokerError, OSError, ValueError):
        if not startup_reported:
            _send_startup_status(ready_connection, STARTUP_FAILED)

    except Exception:
        if not startup_reported:
            _send_startup_status(ready_connection, STARTUP_FAILED)

    finally:
        ready_connection.close()
        if channel is not None:
            channel.close()

        if listener is not None:
            listener.close()

        if service is not None:
            service.close()
            vault = None

        elif vault is not None:
            vault.close()

        if clipboard_guard is not None:
            try:
                clipboard_guard.close()

            except OSError:
                pass

        audit_event("broker_closed")

        if family == "AF_UNIX":
            try:
                Path(address).unlink(missing_ok=True)
            except OSError:
                pass
