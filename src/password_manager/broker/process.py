"""Start and stop the separate Vault Broker process."""

from __future__ import annotations

import multiprocessing
import os
import sys
from multiprocessing.connection import _ConnectionBase
from multiprocessing.process import BaseProcess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Self

from password_manager.broker.client import BrokerClient
from password_manager.broker.exceptions import (
    BrokerCancelledError,
    BrokerError,
    BrokerTransportError,
)
from password_manager.broker.server import (
    STARTUP_CANCELLED,
    STARTUP_READY,
    run_interactive_broker_server,
)
from password_manager.broker.transport import create_local_address, generate_ipc_authkey

STARTUP_TIMEOUT_SECONDS = 15.0
INTERACTIVE_STARTUP_TIMEOUT_SECONDS = 1_800.0
SHUTDOWN_TIMEOUT_SECONDS = 3.0


def _stop_process(process: BaseProcess) -> None:
    process.join(SHUTDOWN_TIMEOUT_SECONDS)

    if process.is_alive():
        process.terminate()
        process.join(SHUTDOWN_TIMEOUT_SECONDS)

    if process.is_alive():
        process.kill()
        process.join(SHUTDOWN_TIMEOUT_SECONDS)


def _receive_startup_status(
    connection: _ConnectionBase[object, object],
    timeout_seconds: float | None = None,
) -> bytes:

    timeout = STARTUP_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds

    try:
        if not connection.poll(timeout):
            raise BrokerTransportError("The Broker process did not become ready safely.")
        return connection.recv_bytes(64)

    except (EOFError, OSError) as error:
        raise BrokerTransportError("The Broker process did not start safely.") from error


class BrokerProcess:
    """A separate Broker process plus its one authenticated client connection."""

    def __init__(
        self,
        process: BaseProcess,
        client: BrokerClient,
        runtime_directory: TemporaryDirectory[str] | None,
    ) -> None:

        self._process = process
        self._client: BrokerClient | None = client
        self._runtime_directory = runtime_directory

    @classmethod
    def start_interactive(
        cls,
        vault_path: str | Path,
        *,
        create_new: bool,
        restore_destination: str | Path | None = None,
    ) -> Self:
        """The child process collects the master passphrase; the interface never receives it."""

        runtime_directory: TemporaryDirectory[str] | None = None

        if sys.platform.startswith("linux"):
            runtime_directory = TemporaryDirectory(prefix="password-manager-v2-runtime-")
            os.chmod(runtime_directory.name, 0o700)

        process: BaseProcess | None = None
        process_started = False

        try:
            address, family = create_local_address(
                None if runtime_directory is None else runtime_directory.name
            )

            authkey = generate_ipc_authkey()
            context = multiprocessing.get_context("spawn")
            ready_receiver, ready_sender = context.Pipe(duplex=False)
            process = context.Process(
                target=run_interactive_broker_server,
                args=(
                    str(Path(vault_path).expanduser().absolute()),
                    address,
                    family,
                    authkey,
                    ready_sender,
                    create_new,
                    None
                    if restore_destination is None
                    else str(Path(restore_destination).expanduser().absolute()),
                ),
                name="PasswordManagerVaultBroker",
                daemon=True,
            )

            process.start()
            process_started = True
            ready_sender.close()

            try:
                startup_status = _receive_startup_status(
                    ready_receiver,
                    INTERACTIVE_STARTUP_TIMEOUT_SECONDS,
                )

            finally:
                ready_receiver.close()

            if startup_status == STARTUP_CANCELLED:
                raise BrokerCancelledError("Vault opening was cancelled.")

            if startup_status != STARTUP_READY:
                raise BrokerTransportError("The Broker could not prepare the vault safely.")

            client = BrokerClient.connect(address, family, authkey)
            return cls(process, client, runtime_directory)

        except Exception:
            if process is not None and process_started:
                _stop_process(process)

            if runtime_directory is not None:
                runtime_directory.cleanup()
            raise

    @property
    def client(self) -> BrokerClient:

        if self._client is None:
            raise BrokerTransportError("The Broker process handle is closed.")
        return self._client

    @property
    def pid(self) -> int | None:
        return self._process.pid

    @property
    def is_alive(self) -> bool:
        return self._process.is_alive()

    def close(self) -> None:
        client = self._client
        self._client = None

        try:
            if client is not None and not client.closed:
                try:
                    client.lock()
                except BrokerError:
                    client.close()

        finally:
            if client is not None:
                client.close()
            _stop_process(self._process)

            if self._runtime_directory is not None:
                self._runtime_directory.cleanup()
                self._runtime_directory = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:

        del exc_type, exc_value, traceback
        self.close()
