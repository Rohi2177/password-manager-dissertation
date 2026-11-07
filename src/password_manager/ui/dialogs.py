"""Account, password-generator and settings dialogs."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from password_manager.core.passwords import (
    DEFAULT_GENERATED_PASSWORD_LENGTH,
    MAX_GENERATED_PASSWORD_LENGTH,
    MIN_GENERATED_PASSWORD_LENGTH,
    generate_password,
)
from password_manager.ui.controller import CredentialInput, CredentialView


class PasswordGeneratorDialog(QDialog):
    """Configure and generate one cryptographically random password."""

    def __init__(self, parent: QWidget | None = None) -> None:

        super().__init__(parent)
        self.setWindowTitle("Password generator")
        self.setModal(True)
        self.setMinimumWidth(500)
        self._selected_password: str | None = None

        self._password = QLineEdit()
        self._password.setReadOnly(True)
        self._password.setAccessibleName("Generated password")

        self._length = QSpinBox()
        self._length.setRange(
            MIN_GENERATED_PASSWORD_LENGTH,
            MAX_GENERATED_PASSWORD_LENGTH,
        )

        self._length.setValue(DEFAULT_GENERATED_PASSWORD_LENGTH)
        self._length.setAccessibleName("Generated password length")

        self._lowercase = QCheckBox("Lowercase letters")
        self._uppercase = QCheckBox("Uppercase letters")
        self._digits = QCheckBox("Numbers")
        self._symbols = QCheckBox("Symbols")
        for option in (self._lowercase, self._uppercase, self._digits, self._symbols):
            option.setChecked(True)

        options = QGroupBox("Character groups")
        options_layout = QGridLayout()
        options_layout.addWidget(self._lowercase, 0, 0)
        options_layout.addWidget(self._uppercase, 0, 1)
        options_layout.addWidget(self._digits, 1, 0)
        options_layout.addWidget(self._symbols, 1, 1)
        options.setLayout(options_layout)

        generate_button = QPushButton("Generate")
        generate_button.setAccessibleName("Generate a new random password")
        generate_button.clicked.connect(self._generate)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )

        use_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        use_button.setText("Use this password")
        buttons.accepted.connect(self._accept_password)
        buttons.rejected.connect(self.reject)

        form = QFormLayout()
        form.addRow("Length:", self._length)
        form.addRow("Generated password:", self._password)

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        layout.addLayout(form)
        layout.addWidget(options)
        layout.addWidget(generate_button)
        layout.addWidget(buttons)
        self.setLayout(layout)
        self._generate()

    @property
    def selected_password(self) -> str | None:

        return self._selected_password

    def _generate(self) -> None:

        try:
            generated = generate_password(
                self._length.value(),
                lowercase=self._lowercase.isChecked(),
                uppercase=self._uppercase.isChecked(),
                digits=self._digits.isChecked(),
                symbols=self._symbols.isChecked(),
            )

        except ValueError as error:
            QMessageBox.warning(self, "Generator settings", str(error))
            return
        self._password.setText(generated)

    def _accept_password(self) -> None:

        generated = self._password.text()

        if not generated:
            self._generate()
            generated = self._password.text()

        if generated:
            self._selected_password = generated
            self.accept()


class CredentialEditorDialog(QDialog):
    """Collect one credential; an empty edit password preserves the old value."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        existing: CredentialView | None = None,
    ) -> None:

        super().__init__(parent)
        self._editing = existing is not None
        self._credential: CredentialInput | None = None
        self.setWindowTitle("Edit credential" if self._editing else "Add credential")
        self.setModal(True)
        self.resize(620, 520)

        self._title = QLineEdit("" if existing is None else existing.title)
        self._website = QLineEdit("" if existing is None else existing.website)
        self._username = QLineEdit("" if existing is None else existing.username)
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._notes = QTextEdit("" if existing is None else existing.notes)
        self._notes.setAcceptRichText(False)

        self._title.setAccessibleName("Credential title")
        self._website.setAccessibleName("Website address")
        self._username.setAccessibleName("Username")
        self._password.setAccessibleName("Credential password")
        self._notes.setAccessibleName("Credential notes")
        self._title.setMaxLength(200)
        self._website.setMaxLength(2048)
        self._username.setMaxLength(512)
        self._password.setMaxLength(4096)

        if self._editing:
            self._password.setPlaceholderText("Leave blank to keep the current password")

        show_password = QCheckBox("Show password")
        show_password.setAccessibleName("Show or hide credential password")
        show_password.toggled.connect(self._toggle_password)

        generator_button = QPushButton("Open password generator…")
        generator_button.setAccessibleName("Open secure password generator")
        generator_button.clicked.connect(self._open_generator)

        password_actions = QHBoxLayout()
        password_actions.addWidget(show_password)
        password_actions.addStretch()
        password_actions.addWidget(generator_button)

        hint = QLabel(
            "Enter the password for this account here. "
            "This form is for an individual website or application credential."
        )

        hint.setWordWrap(True)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.addRow("Title*:", self._title)
        form.addRow("Website:", self._website)
        form.addRow("Username:", self._username)
        form.addRow("Password*:", self._password)
        form.addRow("", password_actions)
        form.addRow("Notes:", self._notes)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(hint)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)
        self._title.setFocus()

    @property
    def credential(self) -> CredentialInput | None:
        return self._credential

    def _toggle_password(self, visible: bool) -> None:
        self._password.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )

    def _open_generator(self) -> None:

        dialog = PasswordGeneratorDialog(self)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            generated = dialog.selected_password

            if generated is not None:
                self._password.setText(generated)

    def _validate_and_accept(self) -> None:
        title = self._title.text().strip()
        password = self._password.text()
        notes = self._notes.toPlainText()

        if not title:
            QMessageBox.warning(self, "Missing title", "Enter a title for this credential.")
            self._title.setFocus()
            return

        if not self._editing and not password:
            QMessageBox.warning(
                self,
                "Missing password",
                "Enter a password or create one with the password generator.",
            )
            self._password.setFocus()
            return

        if len(notes) > 32_768:
            QMessageBox.warning(
                self,
                "Notes too long",
                "Shorten the notes to 32,768 characters or fewer.",
            )
            self._notes.setFocus()
            return
        self._credential = CredentialInput(
            title=title,
            website=self._website.text().strip(),
            username=self._username.text(),
            password=password if password else None,
            notes=notes,
        )
        self.accept()


class CredentialDetailsDialog(QDialog):
    """Show one approved record without requesting its password."""

    def __init__(self, record: CredentialView, parent: QWidget | None = None) -> None:

        super().__init__(parent)
        self.setWindowTitle(f"Credential details — {record.title}")
        self.setModal(True)
        self.resize(580, 430)

        title = QLineEdit(record.title)
        website = QLineEdit(record.website)
        username = QLineEdit(record.username)
        notes = QTextEdit(record.notes)
        for field in (title, website, username):
            field.setReadOnly(True)
        notes.setReadOnly(True)
        notes.setAcceptRichText(False)
        title.setAccessibleName("Credential title")
        website.setAccessibleName("Website address")
        username.setAccessibleName("Username")
        notes.setAccessibleName("Credential notes")

        form = QFormLayout()
        form.addRow("Title:", title)
        form.addRow("Website:", website)
        form.addRow("Username:", username)
        form.addRow("Notes:", notes)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 20, 24, 20)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)


class PasswordRevealDialog(QDialog):
    """Reveal one approved password only while the user holds a button."""

    def __init__(self, password: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._password = password
        self.setWindowTitle("Temporarily reveal password")
        self.setModal(True)
        self.setMinimumWidth(520)

        explanation = QLabel(
            "Press and hold the button (or Space key) to reveal this password. "
            "It hides again when released and this window closes after 20 seconds."
        )

        explanation.setWordWrap(True)

        self._display = QLineEdit()
        self._display.setReadOnly(True)
        self._display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._display.setText("••••••••••••")
        self._display.setAccessibleName("Temporarily revealed password")

        hold = QPushButton("Press and hold to reveal")
        hold.setAccessibleName("Press and hold to reveal the selected password")
        hold.pressed.connect(self._show_password)
        hold.released.connect(self._hide_password)

        close_button = QPushButton("Close and hide")
        close_button.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(explanation)
        layout.addWidget(self._display)
        layout.addWidget(hold)
        layout.addWidget(close_button)
        self.setLayout(layout)

        QTimer.singleShot(20_000, self.accept)
        hold.setFocus()

    def _show_password(self) -> None:
        self._display.setText(self._password)

    def _hide_password(self) -> None:
        self._display.setText("••••••••••••")

    def done(self, result: int) -> None:
        self._hide_password()
        self._password = ""
        super().done(result)


AUTO_LOCK_MINUTE_OPTIONS = (1, 5, 10, 15, 30, 60)


class SettingsDialog(QDialog):
    """Configure automatic locking and show useful security settings."""

    def __init__(
        self,
        auto_lock_minutes: int,
        audit_log_enabled: bool,
        parent: QWidget | None = None,
    ) -> None:

        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumSize(660, 500)

        heading = QLabel("Password Manager")
        heading.setStyleSheet("font-size: 20px; font-weight: 600;")

        body = QLabel(
            "Windows Hello confirms sensitive actions.\n"
            "Copied passwords clear after 30 seconds if the clipboard is unchanged.\n"
            "The vault locks when Windows locks or sleeps.\n\n"
            "Encrypted backups require your master passphrase.\n"
            "Restore a backup to a new file from the home screen.\n\n"
            "Emergency lock shortcut: Ctrl+Shift+L while this application is active.\n"
            f"Security log: {'enabled' if audit_log_enabled else 'unavailable'}."
        )

        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.setAccessibleName("Current application security settings")

        self._auto_lock = QComboBox()
        for minutes in AUTO_LOCK_MINUTE_OPTIONS:
            self._auto_lock.addItem(
                "1 minute" if minutes == 1 else f"{minutes} minutes",
                minutes,
            )

        selected_index = self._auto_lock.findData(auto_lock_minutes)
        self._auto_lock.setCurrentIndex(max(0, selected_index))
        self._auto_lock.setAccessibleName("Automatic vault lock timeout")

        settings_form = QFormLayout()
        settings_form.addRow("Automatically lock after inactivity:", self._auto_lock)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)
        layout.addWidget(heading)
        layout.addWidget(body)
        layout.addLayout(settings_form)
        layout.addStretch()
        layout.addWidget(buttons)
        self.setLayout(layout)

    @property
    def auto_lock_minutes(self) -> int:
        value = self._auto_lock.currentData()
        return value if isinstance(value, int) and value in AUTO_LOCK_MINUTE_OPTIONS else 5
