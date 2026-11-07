"""Pure tests for the untrusted typed adapter without loading Qt widgets."""

import pytest

from password_manager.broker.client import BrokerClient
from password_manager.broker.exceptions import BrokerProtocolError
from password_manager.ui.controller import CredentialInput, VaultController

RECORD_A = "12" * 16
RECORD_B = "34" * 16


def _summary(record_id: str, title: str, version: int = 1) -> dict[str, object]:

    return {
        "record_id": record_id,
        "title": title,
        "username": f"{title.lower()}@example.invalid",
        "version": version,
        "website": f"https://{title.lower()}.example.invalid",
    }


class FakeBrokerClient(BrokerClient):
    __slots__ = ("calls",)

    def __init__(self) -> None:

        self.calls: list[tuple[str, object]] = []

    def list_summaries(self, *, offset: int = 0, limit: int = 50) -> dict[str, object]:

        self.calls.append(("list", (offset, limit)))
        if offset == 0:
            return {"next_offset": 1, "summaries": [_summary(RECORD_A, "Alpha")], "total": 2}
        return {"next_offset": None, "summaries": [_summary(RECORD_B, "Beta")], "total": 2}

    def search_summaries(
        self,
        query: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, object]:

        self.calls.append(("search", (query, offset, limit)))
        return {
            "next_offset": None,
            "summaries": [_summary(RECORD_B, "Beta")],
            "total": 1,
        }

    def view_record(self, record_id: str) -> dict[str, object]:

        self.calls.append(("view", record_id))
        return {
            "record": {
                "notes": "Fake notes",
                "record_id": record_id,
                "title": "Alpha",
                "username": "alpha@example.invalid",
                "version": 1,
                "website": "https://alpha.example.invalid",
            }
        }

    def reveal_password(self, record_id: str) -> dict[str, object]:

        self.calls.append(("reveal", record_id))
        return {"password": "fake-controller-password", "record_id": record_id}

    def copy_password(self, record_id: str) -> dict[str, object]:

        self.calls.append(("copy", record_id))
        return {"copied": True, "record_id": record_id}

    def create_record(self, credential: dict[str, object]) -> dict[str, object]:

        self.calls.append(("create", credential))
        return {"summary": _summary(RECORD_B, "Beta")}

    def create_backup(self, destination: str) -> dict[str, object]:

        self.calls.append(("backup", destination))
        return {"backup_created": True}

    def edit_record(
        self,
        record_id: str,
        credential: dict[str, object],
    ) -> dict[str, object]:

        self.calls.append(("edit", (record_id, credential)))
        return {"summary": _summary(record_id, "Alpha Updated", version=2)}

    def delete_record(self, record_id: str) -> dict[str, object]:

        self.calls.append(("delete", record_id))
        return {"deleted": True, "record_id": record_id}


class UnsafeFakeBrokerClient(FakeBrokerClient):
    def list_summaries(self, *, offset: int = 0, limit: int = 50) -> dict[str, object]:

        del offset, limit
        return {
            "next_offset": None,
            "summaries": [{**_summary(RECORD_A, "Alpha"), "password": "unsafe"}],
            "total": 1,
        }


def _input() -> CredentialInput:

    return CredentialInput(
        title="Example",
        website="https://example.invalid",
        username="fake.user",
        password="fake-input-password",  # noqa: S106
        notes="Fake notes",
    )


def test_controller_paginates_and_searches_safe_summaries() -> None:

    client = FakeBrokerClient()
    controller = VaultController(client)

    listed = controller.summaries()
    searched = controller.summaries("beta")

    assert [item.record_id for item in listed] == [RECORD_A, RECORD_B]
    assert [item.record_id for item in searched] == [RECORD_B]
    assert ("list", (0, 50)) in client.calls
    assert ("list", (1, 50)) in client.calls
    assert ("search", ("beta", 0, 50)) in client.calls


def test_controller_handles_one_record_actions() -> None:
    client = FakeBrokerClient()
    controller = VaultController(client)

    viewed = controller.view(RECORD_A)
    revealed = controller.reveal_password(RECORD_A)
    controller.copy_password(RECORD_A)
    controller.create_backup("/safe/fake-backup.pmvault-backup")
    created = controller.create(_input())
    edited = controller.edit(RECORD_A, _input())
    controller.delete(RECORD_A)

    assert viewed.notes == "Fake notes"
    assert revealed == "fake-controller-password"
    assert created.record_id == RECORD_B
    assert edited.title == "Alpha Updated"
    assert ("copy", RECORD_A) in client.calls
    assert ("backup", "/safe/fake-backup.pmvault-backup") in client.calls
    assert ("delete", RECORD_A) in client.calls


def test_controller_rejects_secret_or_malformed_summary_fields() -> None:

    client = UnsafeFakeBrokerClient()

    with pytest.raises(BrokerProtocolError, match="invalid credential summary"):
        VaultController(client).summaries()
