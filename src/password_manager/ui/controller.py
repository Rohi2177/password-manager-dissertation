"""Validate Broker replies before showing them in the interface."""

from __future__ import annotations

from dataclasses import dataclass

from password_manager.broker.client import BrokerClient
from password_manager.broker.exceptions import BrokerProtocolError

MAX_UI_SUMMARIES = 10_000


def _text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise BrokerProtocolError(f"Broker returned an invalid {field}.")
    return value


def _record_id(value: object) -> str:
    candidate = _text(value, "record ID")

    if len(candidate) != 32:
        raise BrokerProtocolError("Broker returned an invalid record ID.")

    try:
        decoded = bytes.fromhex(candidate)
    except ValueError:
        raise BrokerProtocolError("Broker returned an invalid record ID.") from None

    if len(decoded) != 16 or decoded.hex() != candidate:
        raise BrokerProtocolError("Broker returned an invalid record ID.")
    return candidate


@dataclass(frozen=True, slots=True)
class CredentialSummary:
    record_id: str
    title: str
    website: str
    username: str
    version: int

    @classmethod
    def from_payload(cls, value: object) -> CredentialSummary:
        if not isinstance(value, dict) or set(value) != {
            "record_id",
            "title",
            "username",
            "version",
            "website",
        }:
            raise BrokerProtocolError("Broker returned an invalid credential summary.")
        version = value["version"]

        if type(version) is not int or version < 1:
            raise BrokerProtocolError("Broker returned an invalid credential version.")
        return cls(
            record_id=_record_id(value["record_id"]),
            title=_text(value["title"], "title"),
            website=_text(value["website"], "website"),
            username=_text(value["username"], "username"),
            version=version,
        )


@dataclass(frozen=True, slots=True)
class CredentialView:
    record_id: str
    title: str
    website: str
    username: str
    notes: str
    version: int

    @classmethod
    def from_result(cls, result: object) -> CredentialView:

        if not isinstance(result, dict) or set(result) != {"record"}:
            raise BrokerProtocolError("Broker returned an invalid credential view.")
        record = result["record"]

        if not isinstance(record, dict) or set(record) != {
            "notes",
            "record_id",
            "title",
            "username",
            "version",
            "website",
        }:
            raise BrokerProtocolError("Broker returned an invalid credential view.")
        version = record["version"]

        if type(version) is not int or version < 1:
            raise BrokerProtocolError("Broker returned an invalid credential version.")
        return cls(
            record_id=_record_id(record["record_id"]),
            title=_text(record["title"], "title"),
            website=_text(record["website"], "website"),
            username=_text(record["username"], "username"),
            notes=_text(record["notes"], "notes"),
            version=version,
        )


@dataclass(frozen=True, slots=True)
class CredentialInput:
    title: str
    website: str
    username: str
    password: str | None
    notes: str

    def to_payload(self) -> dict[str, object]:
        return {
            "notes": self.notes,
            "password": self.password,
            "title": self.title,
            "username": self.username,
            "website": self.website,
        }


class VaultController:
    """Expose typed one-record UI operations without importing vault code."""

    def __init__(self, client: BrokerClient) -> None:

        if not isinstance(client, BrokerClient):
            raise TypeError("VaultController requires a BrokerClient.")
        self._client = client

    @property
    def client(self) -> BrokerClient:
        return self._client

    def summaries(self, query: str = "") -> list[CredentialSummary]:
        offset = 0
        summaries: list[CredentialSummary] = []
        seen: set[str] = set()
        while True:
            result = (
                self._client.search_summaries(query, offset=offset)
                if query
                else self._client.list_summaries(offset=offset)
            )

            if not isinstance(result, dict) or set(result) != {
                "next_offset",
                "summaries",
                "total",
            }:
                raise BrokerProtocolError("Broker returned an invalid summary page.")
            total = result["total"]
            page = result["summaries"]
            next_offset = result["next_offset"]

            if type(total) is not int or not 0 <= total <= MAX_UI_SUMMARIES:
                raise BrokerProtocolError("Broker returned an invalid summary total.")

            if not isinstance(page, list) or len(page) > 50:
                raise BrokerProtocolError("Broker returned an invalid summary page.")

            for item in page:
                summary = CredentialSummary.from_payload(item)

                if summary.record_id in seen:
                    raise BrokerProtocolError("Broker returned a duplicate record.")
                seen.add(summary.record_id)
                summaries.append(summary)

            if next_offset is None:
                break
            if type(next_offset) is not int or next_offset <= offset or next_offset > total:
                raise BrokerProtocolError("Broker returned an invalid next offset.")
            offset = next_offset
        if len(summaries) != total:
            raise BrokerProtocolError("Broker summary count does not match.")
        return summaries

    def view(self, record_id: str) -> CredentialView:

        return CredentialView.from_result(self._client.view_record(record_id))

    def reveal_password(self, record_id: str) -> str:

        result = self._client.reveal_password(record_id)
        if not isinstance(result, dict) or set(result) != {"password", "record_id"}:
            raise BrokerProtocolError("Broker returned an invalid password response.")
        if _record_id(result["record_id"]) != record_id:
            raise BrokerProtocolError("Broker returned the wrong record.")
        password = result["password"]

        if not isinstance(password, str) or not password:
            raise BrokerProtocolError("Broker returned an invalid password.")
        return password

    def copy_password(self, record_id: str) -> None:
        result = self._client.copy_password(record_id)

        if result != {"copied": True, "record_id": record_id}:
            raise BrokerProtocolError("Broker returned an invalid copy result.")

    def create(self, credential: CredentialInput) -> CredentialSummary:

        result = self._client.create_record(credential.to_payload())
        return self._summary_result(result)

    def create_backup(self, destination: str) -> None:

        result = self._client.create_backup(destination)

        if result != {"backup_created": True}:
            raise BrokerProtocolError("Broker returned an invalid backup result.")

    def edit(self, record_id: str, credential: CredentialInput) -> CredentialSummary:

        result = self._client.edit_record(record_id, credential.to_payload())
        summary = self._summary_result(result)

        if summary.record_id != record_id:
            raise BrokerProtocolError("Broker returned the wrong edited record.")
        return summary

    def delete(self, record_id: str) -> None:
        result = self._client.delete_record(record_id)

        if result != {"deleted": True, "record_id": record_id}:
            raise BrokerProtocolError("Broker returned an invalid deletion result.")

    @staticmethod
    def _summary_result(result: object) -> CredentialSummary:
        if not isinstance(result, dict) or set(result) != {"summary"}:
            raise BrokerProtocolError("Broker returned an invalid credential result.")
        return CredentialSummary.from_payload(result["summary"])
