"""Passphrase entry and approval dialogs owned by the Broker."""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)

from password_manager.broker.windows_clipboard import (
    clear_clipboard,
    copy_unicode_text,
    read_unicode_text,
)
from password_manager.broker.windows_hello import (
    UserVerifier,
    WindowsHelloResult,
    WindowsHelloVerifier,
    result_explanation,
)
from password_manager.core.passphrases import (
    PassphrasePolicyError,
    normalize_master_passphrase,
    validate_new_master_passphrase,
)
from password_manager.security.clipboard import ClipboardGuard


def _caps_lock_active() -> bool:

    if sys.platform != "win32":
        return False

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        return False
    user32 = windows_library("user32", use_last_error=True)
    get_key_state = user32.GetKeyState
    get_key_state.argtypes = [ctypes.c_int]
    get_key_state.restype = ctypes.c_short
    return bool(get_key_state(0x14) & 1)


def broker_application() -> QApplication:

    current = QApplication.instance()

    if current is not None:
        if not isinstance(current, QApplication):
            raise RuntimeError("The Broker Qt application is invalid.")
        return current
    application = QApplication(["password-manager-vault-broker"])
    application.setApplicationName("Password Manager")
    application.setOrganizationName("University of Sheffield Dissertation")
    return application


class MasterPassphraseDialog(QDialog):
    """Collect a passphrase inside the trusted Broker process."""

    def __init__(
        self,
        vault_name: str,
        *,
        create_new: bool,
        restore_backup: bool = False,
        previous_error: str = "",
        unlock_delay_seconds: int = 0,
    ) -> None:

        super().__init__()
        if create_new and restore_backup:
            raise ValueError("Passphrase-dialog modes are mutually exclusive.")
        self._create_new = create_new
        self._unlock_delay_seconds = max(0, unlock_delay_seconds)

        if create_new:
            self.setWindowTitle("Password Manager — Create vault")

        elif restore_backup:
            self.setWindowTitle("Password Manager — Restore backup")

        else:
            self.setWindowTitle("Password Manager — Unlock vault")

        self.setModal(True)
        self.setMinimumWidth(520)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)

        heading = QLabel(
            "Choose a master passphrase. Keep it safe: it cannot be reset if forgotten."
            if create_new
            else "Enter your master passphrase to open this vault."
        )

        heading.setWordWrap(True)
        heading.setStyleSheet("font-weight: 600; font-size: 14px;")

        vault_label = QLabel(f"Vault: {vault_name}")
        vault_label.setTextFormat(Qt.TextFormat.PlainText)
        vault_label.setWordWrap(True)

        self._passphrase = QLineEdit()
        self._passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self._passphrase.setAccessibleName("Master passphrase")
        self._passphrase.setPlaceholderText(
            "Use five or six unrelated words" if self._create_new else "Enter master passphrase"
        )

        self._confirmation: QLineEdit | None = None
        form = QFormLayout()
        form.addRow("Master passphrase:", self._passphrase)

        if self._create_new:
            self._confirmation = QLineEdit()
            self._confirmation.setEchoMode(QLineEdit.EchoMode.Password)
            self._confirmation.setAccessibleName("Confirm master passphrase")
            form.addRow("Confirm passphrase:", self._confirmation)

        show = QCheckBox("Show passphrase")
        show.setAccessibleName("Show or hide the master passphrase")
        show.toggled.connect(self._toggle_visibility)

        self._caps_warning = QLabel("Caps Lock is on")
        self._caps_warning.setStyleSheet("color: #ffb347; font-weight: 600;")
        self._caps_warning.setVisible(False)

        keyboard_hint = QLabel(
            "Check Caps Lock and your Windows keyboard language before continuing."
        )

        keyboard_hint.setWordWrap(True)

        self._error = QLabel(previous_error)
        self._error.setWordWrap(True)
        self._error.setStyleSheet("color: #ff6b6b;")
        self._error.setVisible(bool(previous_error))
        self._error.setAccessibleName("Passphrase error")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )

        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)

        if create_new:
            ok_button.setText("Create encrypted vault")

        elif restore_backup:
            ok_button.setText("Verify and restore backup")

        else:
            ok_button.setText("Unlock vault")

        self._ok_button = ok_button
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)
        layout.addWidget(heading)
        layout.addWidget(vault_label)
        layout.addLayout(form)
        layout.addWidget(show)
        layout.addWidget(self._caps_warning)
        layout.addWidget(keyboard_hint)
        layout.addWidget(self._error)
        layout.addWidget(buttons)
        self.setLayout(layout)

        self._caps_timer = QTimer(self)
        self._caps_timer.setInterval(400)
        self._caps_timer.timeout.connect(self._refresh_caps_warning)
        self._caps_timer.start()
        self._unlock_timer = QTimer(self)
        self._unlock_timer.setInterval(1_000)
        self._unlock_timer.timeout.connect(self._count_down_unlock_delay)

        if self._unlock_delay_seconds:
            self._set_unlock_enabled(False)
            self._show_unlock_delay()
            self._unlock_timer.start()
        self._passphrase.setFocus()

    @property
    def passphrase(self) -> str:
        return self._passphrase.text()

    def clear_secrets(self) -> None:
        self._passphrase.clear()
        if self._confirmation is not None:
            self._confirmation.clear()

    def _toggle_visibility(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self._passphrase.setEchoMode(mode)
        if self._confirmation is not None:
            self._confirmation.setEchoMode(mode)

    def _refresh_caps_warning(self) -> None:
        self._caps_warning.setVisible(_caps_lock_active())

    def _set_unlock_enabled(self, enabled: bool) -> None:
        self._passphrase.setEnabled(enabled)
        if self._confirmation is not None:
            self._confirmation.setEnabled(enabled)
        self._ok_button.setEnabled(enabled)

    def _show_unlock_delay(self) -> None:
        self._error.setText(
            "Too many unsuccessful attempts. "
            f"Try again in {self._unlock_delay_seconds} second"
            f"{'s' if self._unlock_delay_seconds != 1 else ''}."
        )
        self._error.setVisible(True)

    def _count_down_unlock_delay(self) -> None:
        self._unlock_delay_seconds = max(0, self._unlock_delay_seconds - 1)

        if self._unlock_delay_seconds:
            self._show_unlock_delay()
            return
        self._unlock_timer.stop()
        self._set_unlock_enabled(True)
        self._error.clear()
        self._error.setVisible(False)
        self._passphrase.setFocus()

    def _accept_if_valid(self) -> None:

        if self._unlock_delay_seconds:
            return
        candidate = self._passphrase.text()
        try:
            if self._create_new:
                validated = validate_new_master_passphrase(candidate)
                confirmation = self._confirmation

                if confirmation is None or validated != normalize_master_passphrase(
                    confirmation.text()
                ):
                    raise PassphrasePolicyError("The two master passphrases do not match.")

            else:
                if not normalize_master_passphrase(candidate):
                    raise PassphrasePolicyError("Enter the master passphrase.")

        except PassphrasePolicyError as error:
            self._error.setText(str(error))
            self._error.setVisible(True)
            self._passphrase.setFocus()
            return
        self.accept()


def request_master_passphrase(
    vault_name: str,
    *,
    create_new: bool,
    restore_backup: bool = False,
    previous_error: str = "",
    unlock_delay_seconds: int = 0,
) -> str | None:

    dialog = MasterPassphraseDialog(
        vault_name,
        create_new=create_new,
        restore_backup=restore_backup,
        previous_error=previous_error,
        unlock_delay_seconds=unlock_delay_seconds,
    )

    if dialog.exec() != QDialog.DialogCode.Accepted:
        dialog.clear_secrets()
        return None
    passphrase = dialog.passphrase
    dialog.clear_secrets()
    return passphrase


class BrokerDialogApprovalPolicy:
    """Ask the human from inside the trusted Broker for each sensitive action."""

    _ACTION_LABELS = {
        "create_backup": "create an encrypted backup of the open vault",
        "create_record": "create a new credential",
        "copy_password": "copy the selected password",
        "delete_record": "delete the selected credential",
        "edit_record": "save changes to the selected credential",
        "reveal_password": "temporarily reveal the selected password",
        "view_record": "view the selected credential details",
    }

    def __init__(
        self,
        event_sink: Callable[[str], None] | None = None,
        verifier: UserVerifier | None = None,
    ) -> None:

        self._event_sink = event_sink
        self._verifier = verifier or WindowsHelloVerifier()

    def approve(
        self,
        record_id: str,
        action: str,
        title: str | None = None,
    ) -> bool:

        del record_id
        action_label = self._ACTION_LABELS.get(action)

        if action_label is None:
            return False

        if action == "create_backup":
            target = "the destination selected in the interface"

        else:
            target = "a new credential" if title is None else f"“{title}”"
        message = QMessageBox()
        message.setWindowTitle("Password Manager — Approval")
        message.setIcon(QMessageBox.Icon.Question)
        message.setTextFormat(Qt.TextFormat.PlainText)
        message.setText(f"Allow Password Manager to {action_label}?")
        message.setInformativeText(
            f"Target: {target}\n\nThis approval works once and expires after a few seconds."
        )
        approve_button = message.addButton(
            "Continue to Windows Hello",
            QMessageBox.ButtonRole.AcceptRole,
        )
        message.addButton("Deny", QMessageBox.ButtonRole.RejectRole)
        message.setDefaultButton(approve_button)
        message.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        message.exec()
        wants_verification = message.clickedButton() is approve_button

        if not wants_verification:
            if self._event_sink is not None:
                self._event_sink("capability_denied")
            return False

        owner = QDialog()
        owner.setWindowTitle("Password Manager — Windows Hello")
        owner.setModal(True)
        owner.setMinimumWidth(420)
        owner_layout = QVBoxLayout()
        owner_label = QLabel(
            "Complete the Windows Security check.\nCanceling or failing the check releases nothing."
        )

        owner_label.setWordWrap(True)
        owner_layout.addWidget(owner_label)
        owner.setLayout(owner_layout)
        owner.show()
        owner.raise_()
        owner.activateWindow()
        application = broker_application()
        application.processEvents()
        hello_target = "a new credential" if title is None else f"“{title[:80]}”"

        if action == "create_backup":
            hello_target = "the selected backup destination"
        hello_message = f"Allow Password Manager to {action_label}: {hello_target}"

        try:
            verification = self._verifier.verify(
                int(owner.winId()),
                hello_message[:256],
                pump_events=application.processEvents,
            )

        finally:
            owner.close()
        approved = verification is WindowsHelloResult.VERIFIED

        if not approved:
            denied = QMessageBox()
            denied.setWindowTitle("Password Manager — Request denied")
            denied.setIcon(QMessageBox.Icon.Warning)
            denied.setText(result_explanation(verification))
            denied.setStandardButtons(QMessageBox.StandardButton.Ok)
            denied.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
            denied.exec()

        if self._event_sink is not None:
            self._event_sink("windows_hello_verified" if approved else "windows_hello_denied")
            self._event_sink("capability_approved" if approved else "capability_denied")
        return approved


def copy_password_to_clipboard(password: str) -> None:

    if sys.platform == "win32":
        copy_unicode_text(password)
        return
    application = broker_application()
    application.clipboard().setText(password)


class _BrokerClipboardBackend:
    """Use immediate Win32 operations on Windows and Qt only as a fallback."""

    def write_text(self, text: str) -> None:
        copy_password_to_clipboard(text)

    def read_text(self) -> str | None:
        if sys.platform == "win32":
            return read_unicode_text()
        return broker_application().clipboard().text()

    def clear(self) -> None:
        if sys.platform == "win32":
            clear_clipboard()
            return
        broker_application().clipboard().clear()


def create_clipboard_guard(
    event_sink: Callable[[str], None] | None = None,
) -> ClipboardGuard:

    return ClipboardGuard(_BrokerClipboardBackend(), event_sink=event_sink)


def show_trusted_error(message: str) -> None:

    box = QMessageBox()
    box.setWindowTitle("Password Manager — Error")
    box.setIcon(QMessageBox.Icon.Critical)
    box.setText(message)
    box.setStandardButtons(QMessageBox.StandardButton.Ok)
    box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    box.exec()
