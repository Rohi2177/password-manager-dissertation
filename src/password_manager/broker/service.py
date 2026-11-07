"""Check permissions before accessing a vault record."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from password_manager.broker.capabilities import (
    ALLOWED_CAPABILITY_ACTIONS,
    NEW_RECORD_ID,
    CapabilityManager,
)
from password_manager.broker.exceptions import (
    BrokerDeniedError,
    BrokerLockedError,
    BrokerProtocolError,
)
from password_manager.broker.protocol import (
    BrokerRequest,
    error_message,
    parse_request,
    safe_request_id,
    success_message,
)
from password_manager.core.models import (
    CredentialData,
    CredentialRecord,
    CredentialValidationError,
)
from password_manager.storage import (
    RecordNotFoundError,
    VaultClosedError,
    VaultSession,
    VaultStorageError,
)

MAX_SUMMARIES_PER_PAGE = 50
MAX_SEARCH_CHARACTERS = 200
MAX_DESTINATION_CHARACTERS = 32_767


class ApprovalPolicy(Protocol):
    """Trusted Broker-side decision point for a human-approved action."""

    def approve(
        self,
        record_id: str,
        action: str,
        title: str | None = None,
    ) -> bool: ...


class DenyAllApprovalPolicy:
    """Deny sensitive actions unless an approval policy is supplied."""

    def approve(
        self,
        record_id: str,
        action: str,
        title: str | None = None,
    ) -> bool:

        del record_id, action, title
        return False


def _require_exact_payload(payload: dict[str, object], expected: set[str]) -> None:

    if set(payload) != expected:
        raise BrokerProtocolError("Invalid operation payload.")


def _require_record_id(value: object) -> str:

    if not isinstance(value, str) or len(value) != 32:
        raise BrokerDeniedError("Request denied.")

    try:
        decoded = bytes.fromhex(value)

    except ValueError:
        raise BrokerDeniedError("Request denied.") from None

    if len(decoded) != 16 or decoded.hex() != value:
        raise BrokerDeniedError("Request denied.")
    return value


def _require_action(value: object) -> str:

    if not isinstance(value, str) or value not in ALLOWED_CAPABILITY_ACTIONS:
        raise BrokerDeniedError("Request denied.")
    return value


def _require_destination(value: object) -> Path:

    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_DESTINATION_CHARACTERS
        or "\x00" in value
    ):
        raise BrokerProtocolError("Invalid backup destination.")
    destination = Path(value).expanduser()

    if not destination.is_absolute():
        raise BrokerProtocolError("Invalid backup destination.")
    return destination


def _safe_summary(record: CredentialRecord) -> dict[str, object]:

    return {
        "record_id": record.record_id,
        "title": record.data.title,
        "username": record.data.username,
        "version": record.version,
        "website": record.data.website,
    }


def _credential_from_payload(
    value: object,
    *,
    existing: CredentialData | None = None,
) -> CredentialData:

    if not isinstance(value, dict) or set(value) != {
        "notes",
        "password",
        "title",
        "username",
        "website",
    }:
        raise BrokerProtocolError("Invalid credential payload.")
    title = value["title"]
    website = value["website"]
    username = value["username"]
    password = value["password"]
    notes = value["notes"]

    if not all(isinstance(item, str) for item in (title, website, username, notes)):
        raise BrokerProtocolError("Invalid credential fields.")

    if existing is None:
        if not isinstance(password, str):
            raise BrokerProtocolError("Invalid credential password.")
        selected_password = password

    else:
        if password is None:
            selected_password = existing.password

        elif isinstance(password, str):
            selected_password = password

        else:
            raise BrokerProtocolError("Invalid credential password.")

    try:
        return CredentialData(
            title=title,
            website=website,
            username=username,
            password=selected_password,
            notes=notes,
        )

    except CredentialValidationError as error:
        raise BrokerProtocolError("Invalid credential fields.") from error


class BrokerService:
    """Own one unlocked vault session and expose no bulk-secret operation."""

    def __init__(
        self,
        vault: VaultSession,
        *,
        approval_policy: ApprovalPolicy | None = None,
        capability_manager: CapabilityManager | None = None,
        clipboard_writer: Callable[[str], None] | None = None,
        pid_provider: Callable[[], int] = os.getpid,
    ) -> None:

        if not isinstance(vault, VaultSession):
            raise TypeError("BrokerService requires an unlocked VaultSession.")
        self._vault: VaultSession | None = vault
        self._policy = approval_policy or DenyAllApprovalPolicy()
        self._capabilities = capability_manager or CapabilityManager()
        self._clipboard_writer = clipboard_writer
        self._pid_provider = pid_provider

    @property
    def is_locked(self) -> bool:
        return self._vault is None

    def close(self) -> None:
        self._capabilities.invalidate_all()
        vault = self._vault
        self._vault = None
        if vault is not None:
            vault.close()

    def _unlocked_vault(self) -> VaultSession:

        if self._vault is None:
            raise BrokerLockedError("Broker is locked.")
        return self._vault

    def handle_message(self, message: object) -> dict[str, object]:

        request_id = safe_request_id(message)

        try:
            request = parse_request(message)
            result = self._dispatch(request)
            return success_message(request.request_id, result)

        except BrokerProtocolError:
            return error_message(request_id, "invalid_request", "Invalid request.")

        except BrokerDeniedError:
            return error_message(request_id, "denied", "Request denied.")

        except BrokerLockedError:
            return error_message(request_id, "locked", "Broker is locked.")

        except RecordNotFoundError:
            return error_message(request_id, "denied", "Request denied.")

        except (VaultClosedError, VaultStorageError):
            self.close()
            return error_message(request_id, "internal_error", "Broker locked after an error.")

        except Exception:
            self.close()
            return error_message(request_id, "internal_error", "Broker locked after an error.")

    def _dispatch(self, request: BrokerRequest) -> dict[str, object]:

        operations = {
            "list_summaries": self._list_summaries,
            "lock": self._lock,
            "ping": self._ping,
            "request_capability": self._request_capability,
            "search_summaries": self._search_summaries,
            "use_capability": self._use_capability,
        }

        handler = operations.get(request.operation)

        if handler is None:
            raise BrokerProtocolError("Unsupported operation.")
        return handler(request.payload)

    def _ping(self, payload: dict[str, object]) -> dict[str, object]:

        _require_exact_payload(payload, set())
        return {
            "broker_pid": self._pid_provider(),
            "locked": self.is_locked,
        }

    def _list_summaries(self, payload: dict[str, object]) -> dict[str, object]:
        _require_exact_payload(payload, {"limit", "offset"})
        offset = payload["offset"]
        limit = payload["limit"]

        if type(offset) is not int or not 0 <= offset <= 10_000:
            raise BrokerProtocolError("Invalid summary offset.")

        if type(limit) is not int or not 1 <= limit <= MAX_SUMMARIES_PER_PAGE:
            raise BrokerProtocolError("Invalid summary limit.")

        records = self._unlocked_vault().list_credentials()
        page = records[offset : offset + limit]
        summaries: list[object] = [_safe_summary(record) for record in page]
        candidate_offset = offset + len(page)
        next_offset: int | None = None if candidate_offset >= len(records) else candidate_offset

        return {
            "next_offset": next_offset,
            "summaries": summaries,
            "total": len(records),
        }

    def _search_summaries(self, payload: dict[str, object]) -> dict[str, object]:
        _require_exact_payload(payload, {"limit", "offset", "query"})
        query = payload["query"]
        offset = payload["offset"]
        limit = payload["limit"]

        if not isinstance(query, str) or len(query) > MAX_SEARCH_CHARACTERS:
            raise BrokerProtocolError("Invalid search query.")

        if type(offset) is not int or not 0 <= offset <= 10_000:
            raise BrokerProtocolError("Invalid summary offset.")

        if type(limit) is not int or not 1 <= limit <= MAX_SUMMARIES_PER_PAGE:
            raise BrokerProtocolError("Invalid summary limit.")

        records = self._unlocked_vault().search_credentials(query)
        page = records[offset : offset + limit]
        candidate_offset = offset + len(page)
        return {
            "next_offset": None if candidate_offset >= len(records) else candidate_offset,
            "summaries": [_safe_summary(record) for record in page],
            "total": len(records),
        }

    def _request_capability(self, payload: dict[str, object]) -> dict[str, object]:
        _require_exact_payload(payload, {"action", "record_id"})
        record_id = _require_record_id(payload["record_id"])
        action = _require_action(payload["action"])
        self._unlocked_vault()
        title: str | None = None

        if action in {"create_backup", "create_record"}:
            if record_id != NEW_RECORD_ID:
                raise BrokerDeniedError("Request denied.")

        else:
            record = self._unlocked_vault().get_credential(record_id)
            title = record.data.title

        if not self._policy.approve(record_id, action, title):
            raise BrokerDeniedError("Request denied.")
        token = self._capabilities.issue(record_id, action)
        return {
            "expires_in_seconds": int(self._capabilities.ttl_seconds),
            "token": token,
        }

    def _use_capability(self, payload: dict[str, object]) -> dict[str, object]:

        if set(payload) not in (
            {"action", "record_id", "token"},
            {"action", "credential", "record_id", "token"},
            {"action", "destination", "record_id", "token"},
        ):
            raise BrokerProtocolError("Invalid operation payload.")
        record_id = _require_record_id(payload["record_id"])
        action = _require_action(payload["action"])
        self._capabilities.consume(payload["token"], record_id, action)
        expected_payload = {"action", "record_id", "token"}

        if action in {"create_record", "edit_record"}:
            expected_payload.add("credential")

        elif action == "create_backup":
            expected_payload.add("destination")

        if set(payload) != expected_payload:
            raise BrokerDeniedError("Request denied.")

        vault = self._unlocked_vault()

        if action == "create_backup":
            if record_id != NEW_RECORD_ID:
                raise BrokerDeniedError("Request denied.")
            vault.create_encrypted_backup(_require_destination(payload["destination"]))
            return {"backup_created": True}

        if action == "create_record":
            if record_id != NEW_RECORD_ID:
                raise BrokerDeniedError("Request denied.")

            created_id = vault.add_credential(_credential_from_payload(payload["credential"]))
            created = vault.get_credential(created_id)
            return {"summary": _safe_summary(created)}

        record = vault.get_credential(record_id)

        if action == "view_record":
            return {
                "record": {
                    "notes": record.data.notes,
                    "record_id": record.record_id,
                    "title": record.data.title,
                    "username": record.data.username,
                    "version": record.version,
                    "website": record.data.website,
                }
            }

        if action == "reveal_password":
            return {
                "password": record.data.password,
                "record_id": record.record_id,
            }

        if action == "copy_password":
            if self._clipboard_writer is None:
                raise BrokerDeniedError("Request denied.")
            self._clipboard_writer(record.data.password)
            return {"copied": True, "record_id": record.record_id}

        if action == "edit_record":
            updated = vault.update_credential(
                record_id,
                _credential_from_payload(payload["credential"], existing=record.data),
            )

            return {"summary": _safe_summary(updated)}

        if action == "delete_record":
            vault.delete_credential(record_id)
            return {"deleted": True, "record_id": record_id}
        raise BrokerDeniedError("Request denied.")

    def _lock(self, payload: dict[str, object]) -> dict[str, object]:
        _require_exact_payload(payload, set())
        self.close()
        return {"locked": True}
