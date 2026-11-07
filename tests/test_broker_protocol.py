"""Strict JSON protocol tests for the local Broker boundary."""

import json

import pytest

from password_manager.broker.exceptions import BrokerProtocolError
from password_manager.broker.protocol import (
    BROKER_PROTOCOL_VERSION,
    INVALID_REQUEST_ID,
    MAX_CONTAINER_ITEMS,
    MAX_FRAME_BYTES,
    MAX_JSON_INTEGER,
    MAX_JSON_STRING_CHARACTERS,
    decode_message,
    encode_message,
    error_message,
    parse_request,
    parse_response,
    success_message,
)

REQUEST_ID = "ab" * 16


def _request() -> dict[str, object]:

    return {
        "operation": "ping",
        "payload": {},
        "protocol": BROKER_PROTOCOL_VERSION,
        "request_id": REQUEST_ID,
    }


def test_request_round_trip_uses_strict_json_bytes() -> None:

    message = _request()
    frame = encode_message(message)

    assert isinstance(frame, bytes)
    assert decode_message(frame) == message
    assert parse_request(decode_message(frame)).operation == "ping"


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"[]",
        b'{"same":1,"same":2}',
        b'{"number":1.5}',
        b'{"number":NaN}',
        b"\xff",
    ],
)
def test_invalid_json_frames_are_rejected(frame: bytes) -> None:
    with pytest.raises(BrokerProtocolError):
        decode_message(frame)


def test_oversized_frame_is_rejected_before_json_parsing() -> None:
    with pytest.raises(BrokerProtocolError):
        decode_message(b"x" * (MAX_FRAME_BYTES + 1))


def test_too_deep_json_is_rejected() -> None:
    value: object = "end"
    for _ in range(12):
        value = [value]
    with pytest.raises(BrokerProtocolError):
        encode_message({"nested": value})


@pytest.mark.parametrize(
    "message",
    [
        [],
        {"number": MAX_JSON_INTEGER + 1},
        {"text": "x" * (MAX_JSON_STRING_CHARACTERS + 1)},
        {"items": [None] * (MAX_CONTAINER_ITEMS + 1)},
        {str(index): None for index in range(MAX_CONTAINER_ITEMS + 1)},
        {1: "non-string key"},
        {"unsupported": b"bytes"},
    ],
)
def test_unsupported_python_messages_are_rejected(message: object) -> None:
    with pytest.raises(BrokerProtocolError):
        encode_message(message)


def test_encoded_frame_limit_is_enforced() -> None:
    message = {
        "first": "a" * MAX_JSON_STRING_CHARACTERS,
        "second": "b" * MAX_JSON_STRING_CHARACTERS,
    }

    with pytest.raises(BrokerProtocolError, match="frame limit"):
        encode_message(message)


@pytest.mark.parametrize(
    "change",
    [
        {"extra": True},
        {"protocol": 2},
        {"request_id": "not-an-id"},
        {"operation": "Bulk-Export"},
        {"payload": []},
    ],
)
def test_request_envelope_must_be_exact(change: dict[str, object]) -> None:
    message = _request()
    message.update(change)
    with pytest.raises(BrokerProtocolError):
        parse_request(message)


def test_success_and_error_responses_are_validated() -> None:
    success = parse_response(success_message(REQUEST_ID, {"value": 3}), REQUEST_ID)
    denied = parse_response(error_message(REQUEST_ID, "denied", "Request denied."), REQUEST_ID)

    assert success.ok is True
    assert success.result == {"value": 3}
    assert denied.ok is False
    assert denied.error_code == "denied"


def test_response_for_different_request_is_rejected() -> None:
    message = success_message(REQUEST_ID, {})
    with pytest.raises(BrokerProtocolError):
        parse_response(message, "cd" * 16)


def test_response_builders_reject_invalid_fields() -> None:

    with pytest.raises(BrokerProtocolError):
        success_message("bad-id", {})
    with pytest.raises(BrokerProtocolError):
        error_message(REQUEST_ID, "Bad-Code", "Failure")
    with pytest.raises(BrokerProtocolError):
        error_message(REQUEST_ID, "denied", "")

    response = error_message("bad-id", "denied", "Request denied.")
    assert response["request_id"] == INVALID_REQUEST_ID


@pytest.mark.parametrize(
    "message",
    [
        [],
        {"protocol": 2, "request_id": REQUEST_ID, "ok": True, "result": {}},
        {"protocol": 1, "request_id": REQUEST_ID, "ok": "yes", "result": {}},
        {
            "protocol": 1,
            "request_id": REQUEST_ID,
            "ok": True,
            "result": {},
            "extra": True,
        },
        {"protocol": 1, "request_id": REQUEST_ID, "ok": True, "result": []},
        {"protocol": 1, "request_id": REQUEST_ID, "ok": False, "error": []},
        {
            "protocol": 1,
            "request_id": REQUEST_ID,
            "ok": False,
            "error": {"code": "Bad-Code", "message": "Failure"},
        },
    ],
)
def test_invalid_response_shapes_are_rejected(message: object) -> None:
    with pytest.raises(BrokerProtocolError):
        parse_response(message, REQUEST_ID)


def test_standard_json_decoder_cannot_hide_duplicate_request_fields() -> None:
    frame = json.dumps(_request()).encode()
    duplicate = frame[:-1] + b',"operation":"lock"}'
    with pytest.raises(BrokerProtocolError):
        decode_message(duplicate)
