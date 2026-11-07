"""Exercise the Broker server loop without opening a sandbox-blocked listener."""

from __future__ import annotations

import multiprocessing
import os
from multiprocessing.connection import Connection
from pathlib import Path
from threading import Thread

import pytest
from broker_test_support import run_broker_server

import password_manager.broker.server as broker_server
from password_manager.broker.client import BrokerClient
from password_manager.broker.exceptions import BrokerDeniedError
from password_manager.broker.server import (
    STARTUP_CANCELLED,
    STARTUP_READY,
    _prepare_interactive_vault,
)
from password_manager.broker.transport import JsonChannel
from password_manager.core import Argon2idParameters, CredentialData
from password_manager.core.crypto import MIN_ARGON2_MEMORY_KIB
from password_manager.storage import create_vault, open_vault

FAKE_MASTER_PASSPHRASE = "server loop fake phrase 2026"  # noqa: S105
WRONG_FAKE_MASTER_PASSPHRASE = "server loop wrong phrase 2026"  # noqa: S105
FAKE_PASSWORD = "fake-server-password"  # noqa: S105
FAST_TEST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


class OneConnectionListener:
    def __init__(self, connection: Connection) -> None:

        self._connection = connection
        self.closed = False

    def accept(self) -> Connection:
        return self._connection

    def close(self) -> None:
        self.closed = True


def run_with_inherited_channel(
    vault_path: str,
    record_id: str,
    connection: Connection,
    ready_connection: Connection,
) -> None:

    # The inherited channel tests real process separation without binding a listener.
    listener = OneConnectionListener(connection)
    broker_server.Listener = lambda *args, **kwargs: listener  # type: ignore[assignment,misc]
    run_broker_server(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        "inherited-process-test",
        "TEST",
        b"unused-in-test",
        ready_connection,
        ((record_id, "reveal_password"), (record_id, "delete_record")),
    )


def test_spawned_broker_owns_vault_and_serves_inherited_byte_channel(tmp_path: Path) -> None:
    vault_path, record_id = _vault_with_record(tmp_path)
    context = multiprocessing.get_context("spawn")
    server_connection, client_connection = context.Pipe(duplex=True)
    ready_receiver, ready_sender = context.Pipe(duplex=False)
    process = context.Process(
        target=run_with_inherited_channel,
        args=(str(vault_path), record_id, server_connection, ready_sender),
    )

    process.start()
    server_connection.close()
    ready_sender.close()
    client = BrokerClient(JsonChannel(client_connection))

    try:
        assert ready_receiver.poll(10), "Broker did not report startup"
        assert ready_receiver.recv_bytes() == STARTUP_READY
        status = client.ping()
        assert status == {"broker_pid": process.pid, "locked": False}
        assert process.pid != os.getpid()
        assert FAKE_PASSWORD not in str(client.list_summaries())
        token = client.request_capability(record_id, "reveal_password")
        assert (
            client.use_capability(token, record_id, "reveal_password")["password"] == FAKE_PASSWORD
        )

        with pytest.raises(BrokerDeniedError):
            client.use_capability(token, record_id, "reveal_password")
        assert client.delete_record(record_id)["deleted"] is True
        client.lock()
        process.join(timeout=10)
        assert process.exitcode == 0
        with open_vault(vault_path, FAKE_MASTER_PASSPHRASE) as vault:
            assert vault.list_credentials() == []

    finally:
        ready_receiver.close()
        client.close()

        if process.is_alive():
            process.terminate()
            process.join(timeout=5)


def _vault_with_record(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "server-loop.vault.sqlite3"
    with create_vault(
        path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as vault:
        record_id = vault.add_credential(
            CredentialData(
                title="Server Loop Example",
                website="https://server.example.invalid",
                username="fake.server.user",
                password=FAKE_PASSWORD,
                notes="Fake server test",
            )
        )

    return path, record_id


def test_server_loop_serves_one_authenticated_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    vault_path, record_id = _vault_with_record(tmp_path)
    # On Windows the first end is the named-pipe server handle. Preserve the
    # real client/server orientation so the peer-process-ID check is valid.
    server_connection, client_connection = multiprocessing.Pipe(duplex=True)
    ready_receiver, ready_sender = multiprocessing.Pipe(duplex=False)
    fake_listener = OneConnectionListener(server_connection)
    monkeypatch.setattr(broker_server, "Listener", lambda *args, **kwargs: fake_listener)

    thread = Thread(
        target=run_broker_server,
        args=(
            str(vault_path),
            FAKE_MASTER_PASSPHRASE,
            "inherited-test-channel",
            "TEST",
            b"unused-in-test",
            ready_sender,
            ((record_id, "view_record"),),
        ),
    )

    thread.start()
    assert ready_receiver.recv_bytes() == STARTUP_READY
    ready_receiver.close()

    client = BrokerClient(JsonChannel(client_connection))
    token = client.request_capability(record_id, "view_record")
    viewed = client.use_capability(token, record_id, "view_record")
    assert viewed["record"]["record_id"] == record_id  # type: ignore[index]
    client.lock()

    thread.join(timeout=3)
    assert not thread.is_alive()
    assert fake_listener.closed


def test_server_reports_generic_startup_failure_for_wrong_passphrase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    vault_path, _record_id = _vault_with_record(tmp_path)
    ready_receiver, ready_sender = multiprocessing.Pipe(duplex=False)

    def listener_must_not_start(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("Listener should not start after unlock failure.")

    monkeypatch.setattr(broker_server, "Listener", listener_must_not_start)
    run_broker_server(
        str(vault_path),
        WRONG_FAKE_MASTER_PASSPHRASE,
        "unused",
        "TEST",
        b"unused",
        ready_sender,
    )

    assert ready_receiver.recv_bytes() == STARTUP_CANCELLED
    ready_receiver.close()


def test_invalid_frame_closes_server_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path, _record_id = _vault_with_record(tmp_path)
    # On Windows the first end is the named-pipe server handle.
    server_connection, client_connection = multiprocessing.Pipe(duplex=True)
    ready_receiver, ready_sender = multiprocessing.Pipe(duplex=False)
    fake_listener = OneConnectionListener(server_connection)
    monkeypatch.setattr(broker_server, "Listener", lambda *args, **kwargs: fake_listener)
    thread = Thread(
        target=run_broker_server,
        args=(
            str(vault_path),
            FAKE_MASTER_PASSPHRASE,
            "inherited-test-channel",
            "TEST",
            b"unused-in-test",
            ready_sender,
        ),
    )
    thread.start()
    assert ready_receiver.recv_bytes() == STARTUP_READY
    ready_receiver.close()

    client_connection.send_bytes(b'{"duplicate":1,"duplicate":2}')
    thread.join(timeout=3)

    assert not thread.is_alive()
    assert fake_listener.closed
    client_connection.close()


def test_interactive_restore_prepares_verified_new_vault(tmp_path: Path) -> None:
    source_path, record_id = _vault_with_record(tmp_path)
    backup_path = tmp_path / "server-backup.pmvault-backup"
    restored_path = tmp_path / "server-restored.pmvault"
    with open_vault(source_path, FAKE_MASTER_PASSPHRASE) as source:
        source.create_encrypted_backup(backup_path)

    with _prepare_interactive_vault(
        str(backup_path),
        FAKE_MASTER_PASSPHRASE,
        create_new=False,
        restore_destination=str(restored_path),
    ) as restored:
        assert restored.path == restored_path.absolute()
        assert restored.get_credential(record_id).data.password == FAKE_PASSWORD

    assert backup_path.is_file()
    assert restored_path.is_file()


def test_interactive_create_and_restore_modes_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        _prepare_interactive_vault(
            str(tmp_path / "source.pmvault"),
            FAKE_MASTER_PASSPHRASE,
            create_new=True,
            restore_destination=str(tmp_path / "restored.pmvault"),
        )
