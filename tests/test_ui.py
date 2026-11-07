"""Qt widget checks; skipped only where the host cannot load the Qt runtime."""

import string
from collections.abc import Callable
from pathlib import Path

import pytest

pytest.importorskip(
    "PySide6.QtWidgets",
    reason="Qt runtime is unavailable on this host",
    exc_type=ImportError,
)

from PySide6.QtCore import QSettings, Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
)

from password_manager.broker.trusted_dialogs import (  # noqa: E402
    BrokerDialogApprovalPolicy,
    MasterPassphraseDialog,
)
from password_manager.broker.windows_hello import WindowsHelloResult  # noqa: E402
from password_manager.core.passwords import SAFE_SYMBOLS  # noqa: E402
from password_manager.ui.controller import CredentialView  # noqa: E402
from password_manager.ui.dialogs import (  # noqa: E402
    CredentialEditorDialog,
    PasswordGeneratorDialog,
    PasswordRevealDialog,
    SettingsDialog,
)
from password_manager.ui.main_window import (  # noqa: E402
    _NEW_FILE_DIALOG_OPTIONS,
    MainWindow,
)


@pytest.fixture(autouse=True)
def private_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

    def settings_for_test(*_args: object) -> QSettings:

        return QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)

    monkeypatch.setattr("password_manager.ui.main_window.QSettings", settings_for_test)


def test_main_window_starts_locked_with_vault_actions(qtbot: object) -> None:

    window = MainWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    button_text = {button.text() for button in window.findChildren(QPushButton)}

    assert "Create a new encrypted vault" in button_text
    assert "Open an existing vault" in button_text
    assert "Restore an encrypted backup" in button_text
    assert "Create backup" in button_text
    assert "Generator" not in button_text
    assert "Panic lock" not in button_text
    visible_text = " ".join(label.text() for label in window.findChildren(QLabel))
    assert "Emergency lock shortcut: Ctrl+Shift+L" in visible_text
    assert window.windowTitle() == "Password Manager"
    assert window._controller is None


def test_new_file_dialogs_cannot_use_windows_native_overwrite_prompt() -> None:

    assert _NEW_FILE_DIALOG_OPTIONS & QFileDialog.Option.DontUseNativeDialog
    assert _NEW_FILE_DIALOG_OPTIONS & QFileDialog.Option.DontConfirmOverwrite


def test_settings_preserve_lock_timeout_and_security_information(qtbot: object) -> None:

    dialog = SettingsDialog(10, True)
    qtbot.addWidget(dialog)  # type: ignore[attr-defined]
    text = " ".join(label.text() for label in dialog.findChildren(QLabel))
    timeout = dialog.findChild(QComboBox)
    assert "Windows Hello" in text
    assert "30 seconds" in text
    assert "Encrypted backups require your master passphrase" in text
    assert "Ctrl+Shift+L" in text
    assert timeout is not None
    assert timeout.currentData() == 10
    assert dialog.auto_lock_minutes == 10


def test_throttled_unlock_dialog_enables_after_countdown(qtbot: object) -> None:

    dialog = MasterPassphraseDialog(
        "fake-demo.pmvault",
        create_new=False,
        unlock_delay_seconds=2,
    )

    qtbot.addWidget(dialog)  # type: ignore[attr-defined]

    assert not dialog._passphrase.isEnabled()
    dialog._count_down_unlock_delay()
    assert not dialog._passphrase.isEnabled()
    dialog._count_down_unlock_delay()
    assert dialog._passphrase.isEnabled()


def test_restore_dialog_is_broker_owned_and_does_not_confirm_passphrase(
    qtbot: object,
) -> None:

    dialog = MasterPassphraseDialog(
        "fake-backup.pmvault-backup",
        create_new=False,
        restore_backup=True,
    )

    qtbot.addWidget(dialog)  # type: ignore[attr-defined]
    buttons = {button.text() for button in dialog.findChildren(QPushButton)}
    passphrase_fields = dialog.findChildren(QLineEdit)

    assert dialog.windowTitle().endswith("Restore backup")
    assert "Verify and restore backup" in buttons
    assert len(passphrase_fields) == 1


def test_generator_widget_creates_all_enabled_character_groups(qtbot: object) -> None:

    dialog = PasswordGeneratorDialog()
    qtbot.addWidget(dialog)  # type: ignore[attr-defined]
    generated_fields = [
        field
        for field in dialog.findChildren(QLineEdit)
        if field.accessibleName() == "Generated password"
    ]

    assert len(generated_fields) == 1
    generated = generated_fields[0].text()

    assert len(generated) == 20
    assert any(character in string.ascii_lowercase for character in generated)
    assert any(character in string.ascii_uppercase for character in generated)
    assert any(character in string.digits for character in generated)
    assert any(character in SAFE_SYMBOLS for character in generated)


def test_edit_dialog_blank_password_means_preserve_existing(qtbot: object) -> None:

    existing = CredentialView(
        record_id="12" * 16,
        title="Fake Account",
        website="https://example.invalid",
        username="fake.user",
        notes="Fake notes",
        version=1,
    )
    dialog = CredentialEditorDialog(existing=existing)
    qtbot.addWidget(dialog)  # type: ignore[attr-defined]

    dialog._validate_and_accept()

    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.credential is not None
    assert dialog.credential.password is None


def test_reveal_widget_hides_before_and_after_hold(qtbot: object) -> None:

    dialog = PasswordRevealDialog("fake-temporary-password")
    qtbot.addWidget(dialog)  # type: ignore[attr-defined]

    assert "fake-temporary-password" not in dialog._display.text()
    dialog._show_password()
    assert dialog._display.text() == "fake-temporary-password"
    dialog._hide_password()
    assert "fake-temporary-password" not in dialog._display.text()
    dialog.reject()
    assert dialog._password == ""


def test_trusted_passphrase_dialog_has_required_guidance_and_show_toggle(
    qtbot: object,
) -> None:

    dialog = MasterPassphraseDialog("fake-demo.pmvault", create_new=True)
    qtbot.addWidget(dialog)  # type: ignore[attr-defined]
    guidance = " ".join(label.text() for label in dialog.findChildren(QLabel))
    checkboxes = dialog.findChildren(QCheckBox)
    passphrase_fields = dialog.findChildren(QLineEdit)

    assert any(box.text() == "Show passphrase" for box in checkboxes)
    assert "Caps Lock" in guidance
    assert "keyboard language" in guidance
    assert len(passphrase_fields) == 2
    assert all(field.echoMode() == QLineEdit.EchoMode.Password for field in passphrase_fields)
    show = next(box for box in checkboxes if box.text() == "Show passphrase")
    show.setChecked(True)
    assert all(field.echoMode() == QLineEdit.EchoMode.Normal for field in passphrase_fields)


class _VerifiedHello:
    def __init__(self, result: WindowsHelloResult = WindowsHelloResult.VERIFIED) -> None:

        self.owner_window = 0
        self.message = ""
        self.result = result

    def verify(
        self,
        owner_window: int,
        message: str,
        *,
        pump_events: Callable[[], None] | None = None,
    ) -> WindowsHelloResult:

        del pump_events
        self.owner_window = owner_window
        self.message = message
        return self.result


def test_broker_approval_calls_windows_hello_before_approving(qtbot: object) -> None:

    del qtbot
    verifier = _VerifiedHello()
    events: list[str] = []
    policy = BrokerDialogApprovalPolicy(events.append, verifier)

    def continue_review() -> None:

        for widget in QApplication.topLevelWidgets():
            if not isinstance(widget, QMessageBox):
                continue

            for button in widget.buttons():
                if button.text() == "Continue to Windows Hello":
                    button.click()
                    return
        QTimer.singleShot(10, continue_review)

    QTimer.singleShot(0, continue_review)
    approved = policy.approve("12" * 16, "copy_password", "Fake Email")

    assert approved
    assert verifier.owner_window > 0
    assert "copy the selected password" in verifier.message
    assert "Fake Email" in verifier.message
    assert events == ["windows_hello_verified", "capability_approved"]


@pytest.mark.parametrize("result", [value for value in WindowsHelloResult if value.value != 0])
def test_windows_hello_failure_denies_the_sensitive_action(
    qtbot: object,
    result: WindowsHelloResult,
) -> None:

    del qtbot
    verifier = _VerifiedHello(result)
    events: list[str] = []
    policy = BrokerDialogApprovalPolicy(events.append, verifier)

    def answer_dialogs() -> None:

        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMessageBox) and widget.isVisible():
                assert (
                    widget.textFormat() == Qt.TextFormat.PlainText
                    or "denied" in widget.windowTitle()
                )

                for button in widget.buttons():
                    if button.text() == "Continue to Windows Hello":
                        button.click()
                        return
                widget.accept()

    timer = QTimer()
    timer.timeout.connect(answer_dialogs)
    timer.start(10)

    try:
        assert not policy.approve("12" * 16, "reveal_password", "<b>Fake account</b>")

    finally:
        timer.stop()
    assert events == ["windows_hello_denied", "capability_denied"]


def test_lock_closes_and_clears_an_open_password_reveal(qtbot: object) -> None:

    window = MainWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    dialog = PasswordRevealDialog("fake-revealed-password", window)
    dialog.show()
    dialog._show_password()
    assert "fake-revealed-password" == dialog._display.text()

    window._lock_vault()

    assert not dialog.isVisible()
    assert dialog._password == ""
    assert "fake-revealed-password" != dialog._display.text()


def test_unlock_cannot_accept_while_delay_is_active(qtbot: object) -> None:

    dialog = MasterPassphraseDialog("fake.pmvault", create_new=False, unlock_delay_seconds=2)
    qtbot.addWidget(dialog)  # type: ignore[attr-defined]
    dialog._passphrase.setText("fake master passphrase")
    dialog._accept_if_valid()
    assert dialog.result() != QDialog.DialogCode.Accepted
    dialog._count_down_unlock_delay()
    dialog._count_down_unlock_delay()
    dialog._accept_if_valid()
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_deny_button_does_not_start_windows_hello(qtbot: object) -> None:

    del qtbot
    verifier = _VerifiedHello()
    events: list[str] = []
    policy = BrokerDialogApprovalPolicy(events.append, verifier)

    def deny_request() -> None:

        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QMessageBox) and widget.isVisible():
                for button in widget.buttons():
                    if button.text() == "Deny":
                        button.click()
                        return

    QTimer.singleShot(0, deny_request)
    assert not policy.approve("12" * 16, "copy_password", "Test account")
    assert verifier.owner_window == 0
    assert events == ["capability_denied"]
