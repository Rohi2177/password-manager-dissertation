"""Send requests to the separate Vault Broker."""

from __future__ import annotations

from secrets import token_hex

from password_manager.broker.capabilities import NEW_RECORD_ID
from password_manager.broker.exceptions import (
    BrokerDeniedError,
    BrokerLockedError,
    BrokerProtocolError,
    BrokerTransportError,
)
from password_manager.broker.protocol import BROKER_PROTOCOL_VERSION, parse_response
from password_manager.broker.transport import JsonChannel, connect_local_broker


class BrokerClient:
    """Send strict requests; this object never receives the live Vault Key."""

    def __init__(self, channel: JsonChannel) -> None:
        if not isinstance(channel, JsonChannel):
            raise TypeError("BrokerClient requires a JsonChannel.")
        self._channel: JsonChannel | None = channel

    @property
    def closed(self) -> bool:
        return self._channel is None

    @classmethod
    def connect(cls, address: str, family: str, authkey: bytes) -> BrokerClient:
        return cls(connect_local_broker(address, family, authkey))

    def _open_channel(self) -> JsonChannel:
        if self._channel is None:
            raise BrokerTransportError("The Broker client is closed.")
        return self._channel

    def request(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        channel = self._open_channel()
        request_id = token_hex(16)
        channel.send_message(
            {
                "operation": operation,
                "payload": payload,
                "protocol": BROKER_PROTOCOL_VERSION,
                "request_id": request_id,
            }
        )

        try:
            response = parse_response(channel.receive_message(), request_id)

        except (BrokerProtocolError, BrokerTransportError):
            self.close()
            raise

        if response.ok:
            if response.result is None:
                self.close()
                raise BrokerProtocolError("Broker success response has no result.")
            return response.result

        if response.error_code == "denied":
            raise BrokerDeniedError("Request denied.")

        if response.error_code == "locked":
            raise BrokerLockedError("Broker is locked.")

        if response.error_code == "invalid_request":
            raise BrokerProtocolError("Invalid request.")

        self.close()
        raise BrokerTransportError("The Broker locked after an internal error.")

    def ping(self) -> dict[str, object]:
        return self.request("ping", {})

    def list_summaries(self, *, offset: int = 0, limit: int = 50) -> dict[str, object]:
        return self.request("list_summaries", {"limit": limit, "offset": offset})

    def search_summaries(
        self,
        query: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, object]:

        return self.request(
            "search_summaries",
            {"limit": limit, "offset": offset, "query": query},
        )

    def request_capability(
        self,
        record_id: str,
        action: str,
    ) -> str:

        payload: dict[str, object] = {"action": action, "record_id": record_id}
        result = self.request(
            "request_capability",
            payload,
        )

        token = result.get("token")

        if not isinstance(token, str):
            self.close()

            raise BrokerProtocolError("Broker returned an invalid capability.")
        return token

    def use_capability(
        self,
        token: str,
        record_id: str,
        action: str,
        *,
        credential: dict[str, object] | None = None,
        destination: str | None = None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "action": action,
            "record_id": record_id,
            "token": token,
        }
        if credential is not None:
            payload["credential"] = credential

        if destination is not None:
            payload["destination"] = destination

        return self.request(
            "use_capability",
            payload,
        )

    def view_record(self, record_id: str) -> dict[str, object]:

        token = self.request_capability(record_id, "view_record")
        return self.use_capability(token, record_id, "view_record")

    def reveal_password(self, record_id: str) -> dict[str, object]:

        token = self.request_capability(record_id, "reveal_password")
        return self.use_capability(token, record_id, "reveal_password")

    def copy_password(self, record_id: str) -> dict[str, object]:

        token = self.request_capability(record_id, "copy_password")
        return self.use_capability(token, record_id, "copy_password")

    def create_record(self, credential: dict[str, object]) -> dict[str, object]:

        token = self.request_capability(NEW_RECORD_ID, "create_record")
        return self.use_capability(
            token,
            NEW_RECORD_ID,
            "create_record",
            credential=credential,
        )

    def create_backup(self, destination: str) -> dict[str, object]:

        token = self.request_capability(NEW_RECORD_ID, "create_backup")
        return self.use_capability(
            token,
            NEW_RECORD_ID,
            "create_backup",
            destination=destination,
        )

    def edit_record(
        self,
        record_id: str,
        credential: dict[str, object],
    ) -> dict[str, object]:

        token = self.request_capability(record_id, "edit_record")
        return self.use_capability(
            token,
            record_id,
            "edit_record",
            credential=credential,
        )

    def delete_record(self, record_id: str) -> dict[str, object]:

        token = self.request_capability(record_id, "delete_record")
        return self.use_capability(token, record_id, "delete_record")

    def lock(self) -> None:

        result = self.request("lock", {})

        if result != {"locked": True}:
            self.close()
            raise BrokerProtocolError("Broker lock response is invalid.")

        self.close()

    def close(self) -> None:

        channel = self._channel
        self._channel = None
        if channel is not None:
            channel.close()

    def __enter__(self) -> BrokerClient:

        self._open_channel()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()
