"""Validate bounded JSON messages. Never unpickle client messages."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, TypeGuard

from password_manager.broker.exceptions import BrokerProtocolError

BROKER_PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 128 * 1024
MAX_JSON_DEPTH = 10
MAX_CONTAINER_ITEMS = 256
MAX_JSON_STRING_CHARACTERS = 70_000
MAX_JSON_INTEGER = (1 << 63) - 1
INVALID_REQUEST_ID = "0" * 32

_REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_OPERATION_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,39}\Z")


@dataclass(frozen=True, slots=True)
class BrokerRequest:
    request_id: str
    operation: str
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class BrokerResponse:
    request_id: str
    ok: bool
    result: dict[str, object] | None
    error_code: str | None
    error_message: str | None


def _reject_constant(value: str) -> None:
    raise BrokerProtocolError(f"Unsupported JSON constant: {value}.")


def _reject_float(value: str) -> None:
    raise BrokerProtocolError(f"Floating-point JSON values are not supported: {value}.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerProtocolError("Duplicate JSON object key.")
        result[key] = value
    return result


def _validate_json_value(value: object, *, depth: int = 0) -> None:

    if depth > MAX_JSON_DEPTH:
        raise BrokerProtocolError("JSON message nesting is too deep.")

    if value is None or isinstance(value, bool):
        return

    if type(value) is int:
        if not -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER:
            raise BrokerProtocolError("JSON integer is outside the supported range.")
        return

    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_CHARACTERS:
            raise BrokerProtocolError("JSON string is too long.")
        return

    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise BrokerProtocolError("JSON list contains too many items.")

        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return

    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise BrokerProtocolError("JSON object contains too many items.")

        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 64:
                raise BrokerProtocolError("JSON object key is invalid.")
            _validate_json_value(item, depth=depth + 1)
        return

    raise BrokerProtocolError("JSON value type is unsupported.")


def encode_message(message: object) -> bytes:
    if not isinstance(message, dict):
        raise BrokerProtocolError("A Broker message must be a JSON object.")
    _validate_json_value(message)

    try:
        encoded = json.dumps(
            message,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")

    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise BrokerProtocolError("Broker message cannot be encoded safely.") from error

    if not encoded or len(encoded) > MAX_FRAME_BYTES:
        raise BrokerProtocolError("Broker message exceeds the frame limit.")
    return encoded


def decode_message(frame: object) -> dict[str, object]:

    if not isinstance(frame, bytes) or not frame or len(frame) > MAX_FRAME_BYTES:
        raise BrokerProtocolError("Broker frame is empty or exceeds the limit.")

    try:
        decoded: Any = json.loads(
            frame.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )

    except BrokerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BrokerProtocolError("Broker frame is not valid strict JSON.") from error
    _validate_json_value(decoded)

    if not isinstance(decoded, dict):
        raise BrokerProtocolError("A Broker message must be a JSON object.")
    return decoded


def _valid_request_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _REQUEST_ID_PATTERN.fullmatch(value) is not None


def safe_request_id(message: object) -> str:
    if isinstance(message, dict):
        value = message.get("request_id")
        if _valid_request_id(value):
            return value
    return INVALID_REQUEST_ID


def parse_request(message: object) -> BrokerRequest:

    if not isinstance(message, dict) or set(message) != {
        "protocol",
        "request_id",
        "operation",
        "payload",
    }:
        raise BrokerProtocolError("Invalid request envelope.")

    if type(message["protocol"]) is not int or message["protocol"] != BROKER_PROTOCOL_VERSION:
        raise BrokerProtocolError("Unsupported Broker protocol version.")
    request_id = message["request_id"]
    operation = message["operation"]
    payload = message["payload"]

    if not _valid_request_id(request_id):
        raise BrokerProtocolError("Invalid request ID.")

    if not isinstance(operation, str) or _OPERATION_PATTERN.fullmatch(operation) is None:
        raise BrokerProtocolError("Invalid operation name.")

    if not isinstance(payload, dict):
        raise BrokerProtocolError("Request payload must be an object.")
    return BrokerRequest(request_id=request_id, operation=operation, payload=payload)


def success_message(request_id: str, result: dict[str, object]) -> dict[str, object]:
    if not _valid_request_id(request_id) or not isinstance(result, dict):
        raise BrokerProtocolError("Invalid success response.")
    return {
        "ok": True,
        "protocol": BROKER_PROTOCOL_VERSION,
        "request_id": request_id,
        "result": result,
    }


def error_message(request_id: str, code: str, message: str) -> dict[str, object]:

    if not _valid_request_id(request_id):
        request_id = INVALID_REQUEST_ID

    if _OPERATION_PATTERN.fullmatch(code) is None or not message or len(message) > 200:
        raise BrokerProtocolError("Invalid error response.")
    return {
        "error": {"code": code, "message": message},
        "ok": False,
        "protocol": BROKER_PROTOCOL_VERSION,
        "request_id": request_id,
    }


def parse_response(message: object, expected_request_id: str) -> BrokerResponse:

    if not isinstance(message, dict):
        raise BrokerProtocolError("Invalid response envelope.")

    if (
        type(message.get("protocol")) is not int
        or message.get("protocol") != BROKER_PROTOCOL_VERSION
    ):
        raise BrokerProtocolError("Unsupported response protocol version.")

    if message.get("request_id") != expected_request_id:
        raise BrokerProtocolError("Response request ID does not match.")

    ok = message.get("ok")

    if type(ok) is not bool:
        raise BrokerProtocolError("Response result flag is invalid.")

    if ok:
        if set(message) != {"protocol", "request_id", "ok", "result"}:
            raise BrokerProtocolError("Invalid success response envelope.")
        result = message.get("result")

        if not isinstance(result, dict):
            raise BrokerProtocolError("Response result must be an object.")
        return BrokerResponse(expected_request_id, True, result, None, None)

    if set(message) != {"protocol", "request_id", "ok", "error"}:
        raise BrokerProtocolError("Invalid error response envelope.")

    error = message.get("error")

    if not isinstance(error, dict) or set(error) != {"code", "message"}:
        raise BrokerProtocolError("Invalid error response body.")
    code = error.get("code")
    error_text = error.get("message")

    if (
        not isinstance(code, str)
        or _OPERATION_PATTERN.fullmatch(code) is None
        or not isinstance(error_text, str)
        or not error_text
        or len(error_text) > 200
    ):
        raise BrokerProtocolError("Invalid error response fields.")
    return BrokerResponse(expected_request_id, False, None, code, error_text)
