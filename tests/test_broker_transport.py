"""Tests for bounded local byte transport and endpoint validation."""

import multiprocessing
import os
import sys
from collections.abc import Iterator
from multiprocessing.connection import Connection
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

import password_manager.broker.transport as transport_module
from password_manager.broker.exceptions import BrokerProtocolError, BrokerTransportError
from password_manager.broker.peer import verify_same_user_peer
from password_manager.broker.transport import (
    IPC_AUTHKEY_BYTES,
    JsonChannel,
    connect_local_broker,
    create_local_address,
    generate_ipc_authkey,
)


@pytest.fixture
def short_runtime_directory() -> Iterator[Path]:

    with TemporaryDirectory(prefix="pmv2-") as runtime_name:
        runtime_directory = Path(runtime_name)
        os.chmod(runtime_directory, 0o700)
        yield runtime_directory


def test_ipc_authentication_key_uses_operating_system_randomness() -> None:

    first = generate_ipc_authkey()
    second = generate_ipc_authkey()

    assert len(first) == IPC_AUTHKEY_BYTES
    assert len(second) == IPC_AUTHKEY_BYTES
    assert first != second


def test_windows_address_is_random_named_pipe() -> None:
    first, first_family = create_local_address(platform_name="win32")
    second, second_family = create_local_address(platform_name="win32")

    assert first_family == second_family == "AF_PIPE"
    assert first.startswith(r"\\.\pipe\password-manager-v2-")
    assert first != second


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux permission test")
def test_linux_socket_requires_private_runtime_directory() -> None:

    with TemporaryDirectory(prefix="pmv2-") as runtime_name:
        runtime_directory = Path(runtime_name)
        os.chmod(runtime_directory, 0o755)  # noqa: S103 - deliberately unsafe test case
        with pytest.raises(BrokerTransportError, match="permissions are unsafe"):
            create_local_address(runtime_directory)

        os.chmod(runtime_directory, 0o700)
        address, family = create_local_address(runtime_directory)
        assert family == "AF_UNIX"
        assert Path(address).parent == runtime_directory
        assert Path(address).name.startswith("password-manager-v2-")


def test_unsupported_platform_has_no_transport() -> None:

    with pytest.raises(BrokerTransportError):
        create_local_address(platform_name="darwin")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux path validation")
def test_missing_and_excessively_long_runtime_paths_are_rejected(tmp_path: Path) -> None:

    with pytest.raises(BrokerTransportError, match="unavailable"):
        create_local_address(tmp_path / "missing")

    long_directory = tmp_path / ("a" * 80)
    long_directory.mkdir(mode=0o700)
    with pytest.raises(BrokerTransportError, match="path is too long"):
        create_local_address(long_directory)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux endpoint test")
def test_connect_validates_endpoint_and_authentication_key(
    short_runtime_directory: Path,
) -> None:

    address, family = create_local_address(short_runtime_directory)

    with pytest.raises(BrokerTransportError, match="authentication key"):
        connect_local_broker(address, family, b"short")
    with pytest.raises(BrokerTransportError, match="socket address"):
        connect_local_broker("relative.sock", family, b"K" * 32)
    with pytest.raises(BrokerTransportError, match="pipe address"):
        connect_local_broker(r"\\.\pipe\password-manager-v2-fake", "AF_PIPE", b"K" * 32)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux endpoint test")
def test_connect_returns_verified_json_channel(
    short_runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    address, family = create_local_address(short_runtime_directory)
    client_connection, peer_connection = multiprocessing.Pipe(duplex=True)
    verified: list[str] = []

    def fake_client(
        supplied_address: str,
        *,
        family: str,
        authkey: bytes,
    ) -> Connection:

        assert supplied_address == address
        assert family == "AF_UNIX"
        assert authkey == b"K" * 32
        return client_connection

    def fake_verify(
        connection: Connection,
        *,
        peer_role: str,
    ) -> None:

        assert connection is client_connection
        verified.append(peer_role)

    monkeypatch.setattr(transport_module, "Client", fake_client)
    monkeypatch.setattr(transport_module, "verify_same_user_peer", fake_verify)

    channel = connect_local_broker(address, family, b"K" * 32)
    channel.send_message({"value": 3})

    assert verified == ["server"]
    assert peer_connection.recv_bytes() == b'{"value":3}'
    channel.close()
    peer_connection.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux endpoint test")
def test_connect_closes_connection_when_peer_verification_fails(
    short_runtime_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    address, family = create_local_address(short_runtime_directory)
    client_connection, peer_connection = multiprocessing.Pipe(duplex=True)
    monkeypatch.setattr(transport_module, "Client", lambda *args, **kwargs: client_connection)

    def reject_peer(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise BrokerTransportError("Rejected fake peer.")

    monkeypatch.setattr(transport_module, "verify_same_user_peer", reject_peer)

    with pytest.raises(BrokerTransportError, match="Rejected fake peer"):
        connect_local_broker(address, family, b"K" * 32)

    assert client_connection.closed
    peer_connection.close()


def test_json_channel_round_trip_never_uses_pickle() -> None:

    first_connection, second_connection = multiprocessing.Pipe(duplex=True)
    with JsonChannel(first_connection) as first, JsonChannel(second_connection) as second:
        message: dict[str, object] = {"operation": "ping", "payload": {}}
        first.send_message(message)
        assert second.receive_message() == message


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux peer credential test")
def test_local_pipe_peer_matches_current_user() -> None:

    first_connection, second_connection = multiprocessing.Pipe(duplex=True)

    try:
        verify_same_user_peer(first_connection, peer_role="server")
        verify_same_user_peer(second_connection, peer_role="client")

    finally:
        first_connection.close()
        second_connection.close()


def test_invalid_json_closes_receiving_channel() -> None:

    sender, receiver = multiprocessing.Pipe(duplex=True)
    channel = JsonChannel(receiver)
    sender.send_bytes(b'{"duplicate":1,"duplicate":2}')

    with pytest.raises(BrokerProtocolError):
        channel.receive_message()

    assert channel.closed
    sender.close()


def test_closed_channel_fails_safely() -> None:
    first_connection, second_connection = multiprocessing.Pipe(duplex=True)
    channel = JsonChannel(first_connection)
    channel.close()

    with pytest.raises(BrokerTransportError):
        channel.send_message({})

    second_connection.close()


def test_channel_closes_after_broken_send_or_receive() -> None:

    send_connection, closed_send_peer = multiprocessing.Pipe(duplex=True)
    closed_send_peer.close()
    sender = JsonChannel(send_connection)
    with pytest.raises(BrokerTransportError, match="could not be sent"):
        sender.send_message({"value": 3})
    assert sender.closed

    receive_connection, closed_receive_peer = multiprocessing.Pipe(duplex=True)
    closed_receive_peer.close()
    receiver = JsonChannel(receive_connection)
    with pytest.raises(BrokerTransportError, match="could not be received"):
        receiver.receive_message()
    assert receiver.closed
