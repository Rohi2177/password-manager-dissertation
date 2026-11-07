"""Integration tests proving that the Vault Broker runs in another process."""

import multiprocessing
import os
import socket
import sys
from multiprocessing.connection import _ConnectionBase
from pathlib import Path

import pytest
from broker_test_support import start_test_broker

import password_manager.broker.process as broker_process_module
from password_manager.broker import (
    BrokerCancelledError,
    BrokerDeniedError,
    BrokerProcess,
    BrokerTransportError,
)
from password_manager.broker.process import _receive_startup_status, _stop_process
from password_manager.broker.server import STARTUP_READY
from password_manager.core import Argon2idParameters, CredentialData
from password_manager.core.crypto import MIN_ARGON2_MEMORY_KIB
from password_manager.storage import create_vault

FAKE_MASTER_PASSPHRASE = "separate broker process phrase 2026"  # noqa: S105
WRONG_FAKE_MASTER_PASSPHRASE = "wrong separate process phrase 2026"  # noqa: S105
FAKE_PASSWORD = "separate-process-fake-password"  # noqa: S105
FAST_TEST_PARAMETERS = Argon2idParameters(
    time_cost=2,
    memory_cost_kib=MIN_ARGON2_MEMORY_KIB,
    parallelism=1,
)


def _local_listener_is_available() -> bool:
    if sys.platform == "win32":
        return True
    if not sys.platform.startswith("linux"):
        return False
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError:
        return False
    probe.close()
    return True


LOCAL_LISTENER_AVAILABLE = _local_listener_is_available()


class FakeProcess:
    def __init__(
        self,
        args: tuple[object, ...] = (),
        *,
        alive: bool = False,
        survive_terminate: bool = False,
    ) -> None:

        self.args = args
        self.pid = 4242
        self.started = False
        self.join_count = 0
        self.terminated = False
        self.killed = False
        self._alive = alive
        self._survive_terminate = survive_terminate

    def start(self) -> None:

        self.started = True

        if len(self.args) > 5:
            ready_sender = self.args[4]
            assert isinstance(ready_sender, _ConnectionBase)
            ready_sender.send_bytes(STARTUP_READY)

    def join(self, timeout: float) -> None:
        assert timeout > 0
        self.join_count += 1

    def is_alive(self) -> bool:
        return self._alive

    def terminate(self) -> None:
        self.terminated = True
        if not self._survive_terminate:
            self._alive = False

    def kill(self) -> None:
        self.killed = True
        self._alive = False


class FakeClient:
    def __init__(self, *, lock_error: bool = False) -> None:
        self.closed = False
        self.lock_count = 0
        self.close_count = 0
        self._lock_error = lock_error

    def lock(self) -> None:
        self.lock_count += 1
        if self._lock_error:
            raise BrokerDeniedError("Request denied.")
        self.closed = True

    def close(self) -> None:
        self.close_count += 1
        self.closed = True


class FakeContext:
    def __init__(self, pipe_factory: object) -> None:
        self._pipe_factory = pipe_factory
        self.process: FakeProcess | None = None

    def Pipe(self, *, duplex: bool) -> tuple[object, object]:  # noqa: N802
        assert callable(self._pipe_factory)
        return self._pipe_factory(duplex=duplex)  # type: ignore[no-any-return,operator]

    def Process(self, **kwargs: object) -> FakeProcess:  # noqa: N802
        args = kwargs["args"]
        assert isinstance(args, tuple)
        self.process = FakeProcess(args)
        return self.process


def _create_test_vault(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "separate-process.vault.sqlite3"
    with create_vault(
        path,
        FAKE_MASTER_PASSPHRASE,
        parameters=FAST_TEST_PARAMETERS,
    ) as vault:
        record_id = vault.add_credential(
            CredentialData(
                title="Separate Process Example",
                website="https://process.example.invalid",
                username="fake.process.user",
                password=FAKE_PASSWORD,
                notes="Fake process test",
            )
        )

    return path, record_id


@pytest.mark.skipif(
    not LOCAL_LISTENER_AVAILABLE,
    reason="This sandbox blocks local listener creation; Windows exercises AF_PIPE.",
)
def test_broker_owns_unlocked_vault_in_separate_process(tmp_path: Path) -> None:
    vault_path, record_id = _create_test_vault(tmp_path)

    with start_test_broker(
        vault_path,
        FAKE_MASTER_PASSPHRASE,
        approvals=((record_id, "reveal_password"),),
    ) as broker:
        status = broker.client.ping()
        summaries = broker.client.list_summaries()
        token = broker.client.request_capability(record_id, "reveal_password")
        revealed = broker.client.use_capability(token, record_id, "reveal_password")

        assert broker.is_alive
        assert broker.pid is not None
        assert broker.pid != os.getpid()
        assert status["broker_pid"] == broker.pid
        assert summaries["total"] == 1
        assert FAKE_PASSWORD not in repr(summaries)
        assert revealed == {"password": FAKE_PASSWORD, "record_id": record_id}

        with pytest.raises(BrokerDeniedError):
            broker.client.use_capability(token, record_id, "reveal_password")


@pytest.mark.skipif(
    not LOCAL_LISTENER_AVAILABLE,
    reason="This sandbox blocks local listener creation; Windows exercises AF_PIPE.",
)
def test_separate_process_defaults_to_denying_secret_access(tmp_path: Path) -> None:
    vault_path, record_id = _create_test_vault(tmp_path)

    with start_test_broker(vault_path, FAKE_MASTER_PASSPHRASE) as broker:
        with pytest.raises(BrokerDeniedError):
            broker.client.request_capability(record_id, "view_record")


def test_wrong_passphrase_has_generic_process_start_failure(tmp_path: Path) -> None:
    vault_path, _record_id = _create_test_vault(tmp_path)

    with pytest.raises(BrokerCancelledError):
        start_test_broker(vault_path, WRONG_FAKE_MASTER_PASSPHRASE)


def test_stop_process_escalates_from_terminate_to_kill() -> None:
    process = FakeProcess(alive=True, survive_terminate=True)

    _stop_process(process)  # type: ignore[arg-type]

    assert process.terminated
    assert process.killed
    assert process.join_count == 3


def test_receive_startup_status_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    receiver, sender = multiprocessing.Pipe(duplex=False)
    sender.send_bytes(STARTUP_READY)
    assert _receive_startup_status(receiver) == STARTUP_READY
    receiver.close()
    sender.close()

    timeout_receiver, timeout_sender = multiprocessing.Pipe(duplex=False)
    monkeypatch.setattr(broker_process_module, "STARTUP_TIMEOUT_SECONDS", 0.001)
    with pytest.raises(BrokerTransportError, match="did not become ready"):
        _receive_startup_status(timeout_receiver)
    timeout_receiver.close()
    timeout_sender.close()


def test_mocked_successful_start_and_close(monkeypatch: pytest.MonkeyPatch) -> None:
    real_pipe = multiprocessing.Pipe
    context = FakeContext(real_pipe)
    fake_client = FakeClient()
    runtime_directories: list[str | None] = []

    def fake_address(runtime_directory: str | None) -> tuple[str, str]:
        runtime_directories.append(runtime_directory)
        return "mock-address", "MOCK"

    monkeypatch.setattr(broker_process_module, "create_local_address", fake_address)
    monkeypatch.setattr(broker_process_module, "generate_ipc_authkey", lambda: b"K" * 32)
    monkeypatch.setattr(
        broker_process_module.multiprocessing,
        "get_context",
        lambda _method: context,
    )

    monkeypatch.setattr(
        broker_process_module.BrokerClient,
        "connect",
        lambda _address, _family, _authkey: fake_client,
    )

    broker = start_test_broker("fake.vault.sqlite3", "fake test passphrase")

    assert broker.pid == 4242
    assert broker.client is fake_client
    assert context.process is not None and context.process.started
    assert runtime_directories
    broker.close()
    assert fake_client.lock_count == 1
    assert fake_client.closed
    with pytest.raises(BrokerTransportError, match="handle is closed"):
        _ = broker.client


def test_close_stops_process_when_client_lock_fails() -> None:

    process = FakeProcess()
    client = FakeClient(lock_error=True)
    broker = BrokerProcess(process, client, None)  # type: ignore[arg-type]

    broker.close()

    assert client.lock_count == 1
    assert client.closed
    assert process.join_count == 1
