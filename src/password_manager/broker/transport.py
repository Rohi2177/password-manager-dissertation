"""Authenticated local connections carrying JSON bytes."""

from __future__ import annotations

import os
import stat
import sys
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, _ConnectionBase
from pathlib import Path
from secrets import token_bytes, token_hex

from password_manager.broker.exceptions import BrokerProtocolError, BrokerTransportError
from password_manager.broker.peer import verify_same_user_peer
from password_manager.broker.protocol import MAX_FRAME_BYTES, decode_message, encode_message

IPC_AUTHKEY_BYTES = 32


def generate_ipc_authkey() -> bytes:
    return token_bytes(IPC_AUTHKEY_BYTES)


def _protected_runtime_directory(runtime_directory: str | Path) -> Path:

    directory = Path(runtime_directory).expanduser().absolute()

    try:
        status = directory.stat(follow_symlinks=False)

    except OSError as error:
        raise BrokerTransportError("The protected runtime directory is unavailable.") from error

    if directory.is_symlink() or not stat.S_ISDIR(status.st_mode):
        raise BrokerTransportError("The protected runtime directory is invalid.")

    if hasattr(os, "geteuid") and status.st_uid != os.geteuid():
        raise BrokerTransportError("The protected runtime directory has the wrong owner.")

    if stat.S_IMODE(status.st_mode) & 0o077:
        raise BrokerTransportError("The protected runtime directory permissions are unsafe.")

    return directory


def create_local_address(
    runtime_directory: str | Path | None = None,
    *,
    platform_name: str | None = None,
) -> tuple[str, str]:

    selected_platform = platform_name or sys.platform
    random_name = "password-manager-v2-" + token_hex(16)

    if selected_platform == "win32":
        return rf"\\.\pipe\{random_name}", "AF_PIPE"

    if selected_platform.startswith("linux"):
        if runtime_directory is None:
            raise BrokerTransportError("A protected runtime directory is required.")
        directory = _protected_runtime_directory(runtime_directory)
        address = str(directory / (random_name + ".sock"))

        if len(os.fsencode(address)) > 100:
            raise BrokerTransportError("The local socket path is too long.")

        return address, "AF_UNIX"
    raise BrokerTransportError("This platform has no supported local Broker transport.")


def _validate_endpoint(address: object, family: object) -> tuple[str, str]:

    if not isinstance(address, str) or not isinstance(family, str):
        raise BrokerTransportError("The Broker endpoint is invalid.")

    if family == "AF_PIPE":
        if sys.platform != "win32" or not address.startswith("\\\\.\\pipe\\password-manager-v2-"):
            raise BrokerTransportError("The Windows Broker pipe address is invalid.")

    elif family == "AF_UNIX":
        path = Path(address)

        if (
            not sys.platform.startswith("linux")
            or not path.is_absolute()
            or not path.name.startswith("password-manager-v2-")
            or path.suffix != ".sock"
        ):
            raise BrokerTransportError("The local Broker socket address is invalid.")
        _protected_runtime_directory(path.parent)

    else:
        raise BrokerTransportError("The Broker transport family is unsupported.")
    return address, family


def _validate_authkey(authkey: object) -> bytes:
    if not isinstance(authkey, bytes) or len(authkey) != IPC_AUTHKEY_BYTES:
        raise BrokerTransportError("The Broker authentication key is invalid.")
    return authkey


class JsonChannel:
    """Bounded byte messaging that deliberately never calls send/recv pickle APIs."""

    def __init__(self, connection: _ConnectionBase[object, object]) -> None:

        # Windows uses PipeConnection while POSIX uses Connection. Both are
        # genuine multiprocessing byte connections derived from this base.
        if not isinstance(connection, _ConnectionBase):
            raise BrokerTransportError("The Broker connection is invalid.")
        self._connection: _ConnectionBase[object, object] | None = connection

    @property
    def closed(self) -> bool:
        return self._connection is None

    def _open_connection(self) -> _ConnectionBase[object, object]:

        if self._connection is None:
            raise BrokerTransportError("The Broker connection is closed.")
        return self._connection

    def send_message(self, message: object) -> None:
        connection = self._open_connection()
        frame = encode_message(message)

        try:
            connection.send_bytes(frame)

        except (BrokenPipeError, EOFError, OSError) as error:
            self.close()
            raise BrokerTransportError("The Broker message could not be sent.") from error

    def receive_message(self) -> dict[str, object]:
        connection = self._open_connection()

        try:
            frame = connection.recv_bytes(MAX_FRAME_BYTES)

        except (EOFError, OSError) as error:
            self.close()
            raise BrokerTransportError("The Broker message could not be received.") from error

        try:
            return decode_message(frame)

        except BrokerProtocolError:
            self.close()
            raise

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()

    def __enter__(self) -> JsonChannel:
        self._open_connection()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


def connect_local_broker(address: str, family: str, authkey: bytes) -> JsonChannel:
    validated_address, validated_family = _validate_endpoint(address, family)
    validated_authkey = _validate_authkey(authkey)
    connection: _ConnectionBase[object, object] | None = None

    try:
        connection = Client(
            validated_address,
            family=validated_family,
            authkey=validated_authkey,
        )

        verify_same_user_peer(connection, peer_role="server")
        return JsonChannel(connection)

    except BrokerTransportError:
        if connection is not None:
            connection.close()

        raise
    except (AuthenticationError, OSError, ValueError) as error:
        if connection is not None:
            connection.close()

        raise BrokerTransportError("The local Broker connection failed.") from error
