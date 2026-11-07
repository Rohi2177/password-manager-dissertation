"""Static checks that preserve the vault process and key boundaries."""

import ast
import inspect
from pathlib import Path

from password_manager.broker.process import BrokerProcess

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "password_manager"


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)

        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


def test_visible_ui_does_not_import_vault_or_crypto_implementation() -> None:
    forbidden_prefixes = (
        "password_manager.core.crypto",
        "password_manager.storage",
        "password_manager.broker.service",
    )

    ui_modules = set()

    for path in (SOURCE_ROOT / "ui").glob("*.py"):
        ui_modules.update(_imported_modules(path))

    assert not any(
        module.startswith(prefix) for module in ui_modules for prefix in forbidden_prefixes
    )


def test_broker_client_does_not_import_storage_or_crypto() -> None:
    modules = _imported_modules(SOURCE_ROOT / "broker" / "client.py")

    assert not any(
        module.startswith(("password_manager.storage", "password_manager.core.crypto"))
        for module in modules
    )


def test_only_broker_service_and_server_touch_the_vault_boundary() -> None:
    allowed = {"service.py", "server.py"}
    offenders: list[str] = []

    for path in (SOURCE_ROOT / "broker").glob("*.py"):
        modules = _imported_modules(path)

        if any(module.startswith("password_manager.storage") for module in modules):
            if path.name not in allowed:
                offenders.append(path.name)

    assert offenders == []


def test_interactive_launcher_never_accepts_a_master_passphrase() -> None:

    parameters = inspect.signature(BrokerProcess.start_interactive).parameters

    assert "master_passphrase" not in parameters
    assert set(parameters) == {
        "vault_path",
        "create_new",
        "restore_destination",
    }


def test_visible_ui_does_not_import_broker_owned_trusted_dialogs() -> None:

    ui_modules = set()

    for path in (SOURCE_ROOT / "ui").glob("*.py"):
        ui_modules.update(_imported_modules(path))

    assert "password_manager.broker.trusted_dialogs" not in ui_modules


def test_application_does_not_import_test_approval_helpers() -> None:

    for path in SOURCE_ROOT.rglob("*.py"):
        modules = _imported_modules(path)
        assert not any(
            name == "tests"
            or name.startswith("tests.")
            or name in {"approval_support", "broker_test_support"}
            for name in modules
        ), path
