"""Tests for the untrusted-side Broker client API."""

import multiprocessing
from collections.abc import Callable
from threading import Thread

import pytest

from password_manager.broker.client import BrokerClient
from password_manager.broker.exceptions import (
    BrokerDeniedError,
    BrokerLockedError,
    BrokerProtocolError,
    BrokerTransportError,
)
from password_manager.broker.protocol import error_message, success_message
from password_manager.broker.transport import JsonChannel

RECORD_ID = "12" * 16


def _exchange(
    client_action: Callable[[BrokerClient], object],
    response: Callable[[dict[str, object]], dict[str, object]],
) -> tuple[object, dict[str, object], BrokerClient]:

    client_connection, server_connection = multiprocessing.Pipe(duplex=True)
    client = BrokerClient(JsonChannel(client_connection))
    server = JsonChannel(server_connection)
    received: dict[str, object] = {}

    def respond() -> None:
        request = server.receive_message()
        received.update(request)
        server.send_message(response(request))
        server.close()

    thread = Thread(target=respond)
    thread.start()
    try:
        result = client_action(client)
    finally:
        thread.join(timeout=2)
    assert not thread.is_alive()
    return result, received, client


def _success(
    result: dict[str, object],
) -> Callable[[dict[str, object]], dict[str, object]]:
    def make_response(request: dict[str, object]) -> dict[str, object]:
        request_id = request["request_id"]
        assert isinstance(request_id, str)
        return success_message(request_id, result)

    return make_response


def test_ping_and_summary_convenience_methods() -> None:
    ping, ping_request, ping_client = _exchange(
        lambda client: client.ping(),
        _success({"broker_pid": 42, "locked": False}),
    )
    summaries, summary_request, summary_client = _exchange(
        lambda client: client.list_summaries(offset=5, limit=10),
        _success({"next_offset": None, "summaries": [], "total": 0}),
    )

    assert ping == {"broker_pid": 42, "locked": False}
    assert ping_request["operation"] == "ping"
    assert summaries == {"next_offset": None, "summaries": [], "total": 0}
    assert summary_request["payload"] == {"limit": 10, "offset": 5}
    ping_client.close()
    summary_client.close()


def test_search_summaries_sends_bounded_page_request() -> None:

    result, request, client = _exchange(
        lambda current: current.search_summaries("example", offset=10, limit=20),
        _success({"next_offset": None, "summaries": [], "total": 0}),
    )

    assert result == {"next_offset": None, "summaries": [], "total": 0}
    assert request["operation"] == "search_summaries"
    assert request["payload"] == {"limit": 20, "offset": 10, "query": "example"}
    client.close()


def test_capability_convenience_methods() -> None:

    token, request, request_client = _exchange(
        lambda client: client.request_capability(RECORD_ID, "view_record"),
        _success({"expires_in_seconds": 10, "token": "T" * 43}),
    )

    result, use_request, use_client = _exchange(
        lambda client: client.use_capability("T" * 43, RECORD_ID, "view_record"),
        _success({"record": {"record_id": RECORD_ID}}),
    )

    assert token == "T" * 43
    assert request["operation"] == "request_capability"
    assert result == {"record": {"record_id": RECORD_ID}}
    assert use_request["operation"] == "use_capability"
    request_client.close()
    use_client.close()


def test_create_backup_sends_destination_only_after_capability() -> None:

    result, request, client = _exchange(
        lambda current: current.use_capability(
            "T" * 43,
            "0" * 32,
            "create_backup",
            destination="/safe/fake-backup.pmvault-backup",
        ),
        _success({"backup_created": True}),
    )

    assert result == {"backup_created": True}
    assert request["payload"] == {
        "action": "create_backup",
        "destination": "/safe/fake-backup.pmvault-backup",
        "record_id": "0" * 32,
        "token": "T" * 43,
    }

    client.close()


def test_success_response_without_valid_token_closes_client() -> None:
    clients: list[BrokerClient] = []

    def request_invalid_token(current: BrokerClient) -> object:
        clients.append(current)
        return current.request_capability(RECORD_ID, "view_record")

    with pytest.raises(BrokerProtocolError, match="invalid capability"):
        _exchange(
            request_invalid_token,
            _success({"token": 123}),
        )
    assert clients[0].closed


@pytest.mark.parametrize(
    ("code", "expected_error"),
    [
        ("denied", BrokerDeniedError),
        ("locked", BrokerLockedError),
        ("invalid_request", BrokerProtocolError),
        ("internal_error", BrokerTransportError),
    ],
)
def test_error_responses_map_to_safe_client_errors(
    code: str,
    expected_error: type[Exception],
) -> None:

    def response(request: dict[str, object]) -> dict[str, object]:

        request_id = request["request_id"]
        assert isinstance(request_id, str)
        return error_message(request_id, code, "Generic failure.")

    with pytest.raises(expected_error):
        _exchange(lambda client: client.request("ping", {}), response)


def test_mismatched_response_id_closes_client() -> None:
    clients: list[BrokerClient] = []

    def ping_with_capture(current: BrokerClient) -> object:
        clients.append(current)
        return current.ping()

    with pytest.raises(BrokerProtocolError, match="does not match"):
        _exchange(
            ping_with_capture,
            lambda _request: success_message("34" * 16, {}),
        )
    assert clients[0].closed


def test_lock_closes_client_after_acknowledgement() -> None:
    result, request, client = _exchange(
        lambda current: current.lock(),
        _success({"locked": True}),
    )

    assert result is None
    assert request["operation"] == "lock"
    assert client.closed


def test_closed_client_rejects_requests() -> None:

    first_connection, second_connection = multiprocessing.Pipe(duplex=True)
    client = BrokerClient(JsonChannel(first_connection))
    client.close()
    second_connection.close()

    with pytest.raises(BrokerTransportError, match="closed"):
        client.ping()
