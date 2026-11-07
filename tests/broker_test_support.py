"""Drive the real interactive Broker with fake user input during tests."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from approval_support import OneShotApprovalPolicy

import password_manager.broker.process as process_module
from password_manager.broker.process import BrokerProcess
from password_manager.broker.server import run_interactive_broker_server
from password_manager.security.clipboard import ClipboardGuard


class MemoryClipboard:
    def __init__(self):
        self.text = None

    def write_text(self, text):
        self.text = text

    def read_text(self):
        return self.text

    def clear(self):
        self.text = None


def run_test_interactive_server(
    vault_path,
    address,
    family,
    authkey,
    ready_connection,
    create_new,
    restore_destination,
    master_passphrase,
    approvals,
):

    from password_manager.broker import trusted_dialogs

    responses = iter((master_passphrase, None))
    application = SimpleNamespace(processEvents=lambda: None)
    policy = OneShotApprovalPolicy(approvals)
    with (
        patch.object(trusted_dialogs, "broker_application", return_value=application),
        patch.object(
            trusted_dialogs,
            "request_master_passphrase",
            side_effect=lambda *args, **kwargs: next(responses),
        ),
        patch.object(trusted_dialogs, "show_trusted_error"),
        patch.object(trusted_dialogs, "BrokerDialogApprovalPolicy", return_value=policy),
        patch.object(
            trusted_dialogs,
            "create_clipboard_guard",
            side_effect=lambda event_sink: ClipboardGuard(MemoryClipboard(), event_sink=event_sink),
        ),
    ):
        run_interactive_broker_server(
            vault_path,
            address,
            family,
            authkey,
            ready_connection,
            create_new,
            restore_destination,
        )


def run_broker_server(
    vault_path,
    master_passphrase,
    address,
    family,
    authkey,
    ready_connection,
    approvals=(),
):

    run_test_interactive_server(
        vault_path,
        address,
        family,
        authkey,
        ready_connection,
        False,
        None,
        master_passphrase,
        approvals,
    )


def start_test_broker(
    vault_path: str | Path,
    master_passphrase: str,
    *,
    approvals: tuple[tuple[str, str], ...] = (),
) -> BrokerProcess:

    context = process_module.multiprocessing.get_context("spawn")

    def make_process(**kwargs):
        kwargs["target"] = run_test_interactive_server
        kwargs["args"] += (master_passphrase, approvals)
        return context.Process(**kwargs)

    test_context = SimpleNamespace(Pipe=context.Pipe, Process=make_process)
    with patch.object(process_module.multiprocessing, "get_context", return_value=test_context):
        return BrokerProcess.start_interactive(vault_path, create_new=False)
