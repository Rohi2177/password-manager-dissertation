"""Display the vault and send approved actions to the Broker."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import cast

from PySide6.QtCore import QByteArray, QEvent, QObject, QSettings, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence, QShortcut, QShowEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from password_manager.broker import (
    BrokerCancelledError,
    BrokerDeniedError,
    BrokerError,
    BrokerProcess,
)
from password_manager.config import APP_NAME, SETTINGS_APPLICATION, SETTINGS_ORGANIZATION
from password_manager.security import InactivityGuard, cloud_sync_provider
from password_manager.security.audit import SecurityAuditLog
from password_manager.security.windows_events import (
    lock_event_for_windows_message,
    message_and_parameter,
    register_session_notifications,
    unregister_session_notifications,
)
from password_manager.security.windows_session import is_windows_session_locked
from password_manager.ui.controller import CredentialSummary, VaultController
from password_manager.ui.dialogs import (
    CredentialDetailsDialog,
    CredentialEditorDialog,
    PasswordRevealDialog,
    SettingsDialog,
)

VAULT_FILTER = "Password Manager vault (*.pmvault *.sqlite3);;All files (*)"
BACKUP_FILTER = "Encrypted vault backup (*.pmvault-backup *.pmvault *.sqlite3);;All files (*)"
DEFAULT_AUTO_LOCK_MINUTES = 5
AUTO_LOCK_SETTING = "security/auto_lock_minutes"
_NEW_FILE_DIALOG_OPTIONS = (
    QFileDialog.Option.DontUseNativeDialog | QFileDialog.Option.DontConfirmOverwrite
)
_ACTIVITY_EVENTS = frozenset(
    {
        QEvent.Type.KeyPress,
        QEvent.Type.MouseButtonPress,
        QEvent.Type.MouseButtonDblClick,
        QEvent.Type.MouseMove,
        QEvent.Type.TouchBegin,
        QEvent.Type.Wheel,
    }
)


class MainWindow(QMainWindow):
    """Coordinate the untrusted UI with one isolated interactive Broker."""

    def __init__(self) -> None:

        super().__init__()
        try:
            self._audit: SecurityAuditLog | None = SecurityAuditLog("ui")
        except OSError:
            self._audit = None
        self._audit_event("application_started")
        self._broker: BrokerProcess | None = None
        self._controller: VaultController | None = None
        self._vault_path: Path | None = None
        self._session_notifications_registered = False
        self._settings = QSettings(SETTINGS_ORGANIZATION, SETTINGS_APPLICATION)
        self._auto_lock_minutes = self._load_auto_lock_minutes()
        self._activity_guard = InactivityGuard(self._auto_lock_minutes * 60)
        self._security_timer = QTimer(self)
        self._security_timer.setInterval(1_000)
        self._security_timer.timeout.connect(self._check_security_lock)
        self._security_timer.start()
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(250)
        self._search_timer.timeout.connect(self._refresh_entries)

        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(880, 560)
        self.resize(1080, 700)

        self._pages = QStackedWidget()
        self._welcome_page = self._build_welcome_page()
        self._vault_page = self._build_vault_page()
        self._pages.addWidget(self._welcome_page)
        self._pages.addWidget(self._vault_page)
        self.setCentralWidget(self._pages)
        self.statusBar().showMessage("Ready — no vault is open.")
        self._install_shortcuts()
        application = QApplication.instance()
        if application is not None:
            application.installEventFilter(self)

    def _load_auto_lock_minutes(self) -> int:
        value = self._settings.value(AUTO_LOCK_SETTING, DEFAULT_AUTO_LOCK_MINUTES)

        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return DEFAULT_AUTO_LOCK_MINUTES

        try:
            minutes = int(value)
        except (TypeError, ValueError):
            return DEFAULT_AUTO_LOCK_MINUTES
        return minutes if minutes in (1, 5, 10, 15, 30, 60) else DEFAULT_AUTO_LOCK_MINUTES

    def _audit_event(self, event: str) -> None:

        if self._audit is not None:
            try:
                self._audit.record(event)
            except OSError:
                self._audit = None

    def _build_welcome_page(self) -> QWidget:
        title = QLabel(APP_NAME)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 30px; font-weight: 650;")
        title.setAccessibleName("Password Manager title")

        explanation = QLabel("Store and manage your passwords on this computer.")
        explanation.setAlignment(Qt.AlignmentFlag.AlignCenter)
        explanation.setWordWrap(True)
        explanation.setAccessibleName("Offline password manager")

        create_button = QPushButton("Create a new encrypted vault")
        create_button.setMinimumHeight(46)
        create_button.setAccessibleName("Create a new encrypted password vault")
        create_button.clicked.connect(self._choose_new_vault)

        open_button = QPushButton("Open an existing vault")
        open_button.setMinimumHeight(46)
        open_button.setAccessibleName("Open an existing encrypted password vault")
        open_button.clicked.connect(self._choose_existing_vault)

        restore_button = QPushButton("Restore an encrypted backup")
        restore_button.setMinimumHeight(46)
        restore_button.setAccessibleName("Verify and restore an encrypted vault backup")
        restore_button.clicked.connect(self._restore_encrypted_backup)

        layout = QVBoxLayout()
        layout.setContentsMargins(120, 70, 120, 70)
        layout.setSpacing(22)
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(explanation)
        layout.addSpacing(12)
        layout.addWidget(create_button)
        layout.addWidget(open_button)
        layout.addWidget(restore_button)
        layout.addStretch()

        page = QWidget()
        page.setLayout(layout)
        return page

    def _build_vault_page(self) -> QWidget:
        self._vault_heading = QLabel("Encrypted vault")
        self._vault_heading.setTextFormat(Qt.TextFormat.PlainText)
        self._vault_heading.setStyleSheet("font-size: 22px; font-weight: 600;")
        self._vault_heading.setAccessibleName("Open vault name")

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search title, website, username or notes…")
        self._search.setClearButtonEnabled(True)
        self._search.setAccessibleName("Search credentials")
        self._search.textChanged.connect(lambda _text: self._search_timer.start())

        add_button = QPushButton("Add credential")
        add_button.setAccessibleName("Add a new credential")
        add_button.clicked.connect(self._add_credential)

        backup_button = QPushButton("Create backup")
        backup_button.setAccessibleName("Create a verified encrypted vault backup")
        backup_button.clicked.connect(self._create_encrypted_backup)

        settings_button = QPushButton("Settings")
        settings_button.clicked.connect(self._show_settings)

        lock_button = QPushButton("Lock vault")
        lock_button.setAccessibleName("Lock the vault")
        lock_button.setToolTip("Lock normally with Ctrl+L. Emergency shortcut: Ctrl+Shift+L.")
        lock_button.clicked.connect(self._lock_vault)

        emergency_hint = QLabel("Emergency lock shortcut: Ctrl+Shift+L")
        emergency_hint.setAlignment(Qt.AlignmentFlag.AlignRight)
        emergency_hint.setAccessibleName("Emergency lock keyboard shortcut Control Shift L")

        top_actions = QHBoxLayout()
        top_actions.addWidget(add_button)
        top_actions.addWidget(backup_button)
        top_actions.addStretch()
        top_actions.addWidget(settings_button)
        top_actions.addWidget(lock_button)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Title", "Username", "Website"])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setAccessibleName("Credential list")
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.itemSelectionChanged.connect(self._update_action_state)
        self._table.itemDoubleClicked.connect(lambda _item: self._view_credential())

        self._view_button = QPushButton("View details")
        self._edit_button = QPushButton("Edit")
        self._copy_button = QPushButton("Copy password")
        self._reveal_button = QPushButton("Reveal")
        self._delete_button = QPushButton("Delete")
        self._view_button.clicked.connect(self._view_credential)
        self._edit_button.clicked.connect(self._edit_credential)
        self._copy_button.clicked.connect(self._copy_password)
        self._reveal_button.clicked.connect(self._reveal_password)
        self._delete_button.clicked.connect(self._delete_credential)
        self._view_button.setAccessibleName("View selected credential details")
        self._edit_button.setAccessibleName("Edit selected credential")
        self._copy_button.setAccessibleName("Copy selected password")
        self._reveal_button.setAccessibleName("Temporarily reveal selected password")
        self._delete_button.setAccessibleName("Delete selected credential")

        record_actions = QHBoxLayout()
        record_actions.addWidget(self._view_button)
        record_actions.addWidget(self._edit_button)
        record_actions.addWidget(self._copy_button)
        record_actions.addWidget(self._reveal_button)
        record_actions.addStretch()
        record_actions.addWidget(self._delete_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)
        layout.addWidget(self._vault_heading)
        layout.addLayout(top_actions)
        layout.addWidget(emergency_hint)
        layout.addWidget(self._search)
        layout.addWidget(self._table, 1)
        layout.addLayout(record_actions)

        page = QWidget()
        page.setLayout(layout)
        self._update_action_state()
        return page

    def _install_shortcuts(self) -> None:
        add_action = QAction("Add credential", self)
        add_action.setShortcut(QKeySequence.StandardKey.New)
        add_action.triggered.connect(self._add_credential)
        self.addAction(add_action)

        search_shortcut = QShortcut(QKeySequence.StandardKey.Find, self)
        search_shortcut.activated.connect(self._focus_search)
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(self._lock_vault)
        emergency_shortcut = QShortcut(QKeySequence("Ctrl+Shift+L"), self)
        emergency_shortcut.setContext(Qt.ShortcutContext.ApplicationShortcut)
        emergency_shortcut.activated.connect(self._emergency_lock)
        QShortcut(QKeySequence("Delete"), self).activated.connect(self._delete_credential)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:

        if self._controller is not None and event.type() in _ACTIVITY_EVENTS:
            self._activity_guard.mark_activity()
        return super().eventFilter(watched, event)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)

        if not self._session_notifications_registered:
            self._session_notifications_registered = register_session_notifications(
                int(self.winId())
            )

    def nativeEvent(
        self,
        event_type: QByteArray | bytes | bytearray | memoryview[int],
        message: int,
    ) -> tuple[bool, int]:

        decoded = message_and_parameter(int(message))
        if decoded is not None and self._controller is not None:
            audit_event = lock_event_for_windows_message(*decoded)

            if audit_event is not None:
                status = (
                    "Vault locked because Windows is suspending."
                    if audit_event == "vault_locked_power"
                    else "Vault locked because the Windows session changed."
                )

                QTimer.singleShot(0, lambda: self._perform_lock(status, audit_event))
        return cast(tuple[bool, int], super().nativeEvent(event_type, message))

    def _check_security_lock(self) -> None:

        if self._controller is None:
            return

        if is_windows_session_locked():
            self._perform_lock(
                "Vault locked because the Windows session is unavailable.",
                "vault_locked_session",
            )
            return

        if self._activity_guard.expired():
            self._perform_lock(
                f"Vault automatically locked after {self._auto_lock_minutes} "
                f"minute{'s' if self._auto_lock_minutes != 1 else ''} of inactivity.",
                "vault_locked_inactivity",
            )

    def _focus_search(self) -> None:
        if self._controller is not None:
            self._search.setFocus()
            self._search.selectAll()

    def _choose_new_vault(self) -> None:
        selected, _filter = QFileDialog.getSaveFileName(
            self,
            "Create encrypted vault",
            str(Path.home() / "password-manager.pmvault"),
            VAULT_FILTER,
            options=_NEW_FILE_DIALOG_OPTIONS,
        )

        if not selected:
            return
        path = Path(selected)
        if not path.suffix:
            path = path.with_suffix(".pmvault")

        if path.exists():
            QMessageBox.warning(
                self,
                "Choose a new file",
                "That file already exists. Choose a different name for the new vault.",
            )
            return
        if not self._confirm_cloud_location(path, "The new vault location"):
            return
        self._start_interactive_broker(path, create_new=True)

    def _choose_existing_vault(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Open encrypted vault",
            str(Path.home()),
            VAULT_FILTER,
        )

        if selected:
            path = Path(selected)
            if not self._confirm_cloud_location(path, "The selected vault"):
                return
            self._start_interactive_broker(path, create_new=False)

    def _restore_encrypted_backup(self) -> None:

        if self._broker is not None:
            return
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select encrypted backup to restore",
            str(Path.home()),
            BACKUP_FILTER,
        )

        if not selected:
            return
        source = Path(selected)

        if not self._confirm_cloud_location(source, "The selected backup"):
            return
        suggested = Path.home() / f"restored-{source.stem}.pmvault"
        destination_text, _filter = QFileDialog.getSaveFileName(
            self,
            "Restore to a new encrypted vault",
            str(suggested),
            VAULT_FILTER,
            options=_NEW_FILE_DIALOG_OPTIONS,
        )

        if not destination_text:
            return
        destination = Path(destination_text)

        if not destination.suffix:
            destination = destination.with_suffix(".pmvault")

        if destination.exists():
            QMessageBox.warning(
                self,
                "Choose a new file",
                "Restore never overwrites a file. Choose a new destination name.",
            )
            return
        try:
            same_file = source.resolve(strict=False) == destination.resolve(strict=False)
        except (OSError, RuntimeError):
            same_file = False

        if same_file:
            QMessageBox.warning(
                self,
                "Choose a different file",
                "The restored vault must use a different file from the selected backup.",
            )

            return
        if not self._confirm_cloud_location(destination, "The restored vault location"):
            return
        self._start_interactive_broker(
            source,
            create_new=False,
            restore_destination=destination,
        )

    def _confirm_cloud_location(self, path: Path, description: str) -> bool:

        provider = cloud_sync_provider(path)
        if provider is None:
            return True
        choice = QMessageBox.warning(
            self,
            "Cloud-synchronised location",
            f"{description} appears to be inside {provider}. The encrypted file may be "
            "uploaded or copied to other devices by that service.\n\nChoose a different "
            "folder for laptop-only storage. Continue with this location?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )

        return choice == QMessageBox.StandardButton.Yes

    def _start_interactive_broker(
        self,
        path: Path,
        *,
        create_new: bool,
        restore_destination: Path | None = None,
    ) -> None:

        if self._broker is not None:
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            broker = BrokerProcess.start_interactive(
                path,
                create_new=create_new,
                restore_destination=restore_destination,
            )
            status = broker.client.ping()
            broker_pid = status.get("broker_pid")

            if (
                status.get("locked") is not False
                or type(broker_pid) is not int
                or broker_pid <= 0
                or broker_pid == os.getpid()
                or broker_pid != broker.pid
            ):
                broker.close()
                raise BrokerError("The trusted Broker returned an invalid status.")
        except BrokerCancelledError:
            self.statusBar().showMessage(
                "Backup restoration cancelled."
                if restore_destination is not None
                else "Vault opening cancelled.",
                5_000,
            )

            return
        except (BrokerError, OSError):
            QMessageBox.critical(
                self,
                "Restore unavailable" if restore_destination is not None else "Vault unavailable",
                "The encrypted backup could not be verified and restored safely. No vault is open."
                if restore_destination is not None
                else "The encrypted vault could not be prepared safely. No vault is open.",
            )

            return
        finally:
            QApplication.restoreOverrideCursor()

        self._broker = broker
        self._audit_event(
            "vault_created"
            if create_new
            else "backup_restored"
            if restore_destination is not None
            else "unlock_succeeded"
        )

        self._controller = VaultController(broker.client)
        active_path = path if restore_destination is None else restore_destination
        self._vault_path = active_path
        self._activity_guard.mark_activity()
        self._vault_heading.setText(f"Vault: {active_path.name}")
        self._pages.setCurrentWidget(self._vault_page)
        self._refresh_entries()
        self.statusBar().showMessage(
            "Backup restored. Your vault is open."
            if restore_destination is not None
            else "Vault unlocked.",
            10_000,
        )

    def _selected_record_id(self) -> str | None:

        selected = self._table.selectedItems()
        if not selected:
            return None
        record_id = selected[0].data(Qt.ItemDataRole.UserRole)
        return record_id if isinstance(record_id, str) else None

    def _update_action_state(self) -> None:
        enabled = self._selected_record_id() is not None and self._controller is not None
        for button in (
            self._view_button,
            self._edit_button,
            self._copy_button,
            self._reveal_button,
            self._delete_button,
        ):
            button.setEnabled(enabled)

    def _refresh_entries(self, preferred_record_id: str | None = None) -> None:
        controller = self._controller

        if controller is None:
            return
        try:
            summaries = controller.summaries(self._search.text().strip())
        except BrokerError as error:
            self._handle_broker_error(error)
            return
        self._fill_table(summaries, preferred_record_id)
        count = len(summaries)
        self.statusBar().showMessage(f"{count} credential{'s' if count != 1 else ''} shown.")

    def _fill_table(
        self,
        summaries: list[CredentialSummary],
        preferred_record_id: str | None,
    ) -> None:

        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(summaries))
        preferred_row: int | None = None
        for row, summary in enumerate(summaries):
            title = QTableWidgetItem(summary.title)
            title.setData(Qt.ItemDataRole.UserRole, summary.record_id)
            self._table.setItem(row, 0, title)
            self._table.setItem(row, 1, QTableWidgetItem(summary.username))
            self._table.setItem(row, 2, QTableWidgetItem(summary.website))
            if summary.record_id == preferred_record_id:
                preferred_row = row
        self._table.setSortingEnabled(True)
        self._table.resizeColumnToContents(0)
        self._table.resizeColumnToContents(1)
        if preferred_row is not None:
            self._table.selectRow(preferred_row)
        self._update_action_state()

    def _add_credential(self) -> None:
        controller = self._controller
        if controller is None:
            return
        dialog = CredentialEditorDialog(self)

        if dialog.exec() != dialog.DialogCode.Accepted or dialog.credential is None:
            return
        try:
            created = controller.create(dialog.credential)
        except BrokerError as error:
            self._handle_broker_error(error)
            return
        self._refresh_entries(created.record_id)
        self.statusBar().showMessage("Credential added after approval.", 7_000)

    def _view_credential(self) -> None:
        controller = self._controller
        record_id = self._selected_record_id()

        if controller is None or record_id is None:
            return
        try:
            record = controller.view(record_id)
        except BrokerError as error:
            self._handle_broker_error(error)
            return
        CredentialDetailsDialog(record, self).exec()

    def _edit_credential(self) -> None:
        controller = self._controller
        record_id = self._selected_record_id()
        if controller is None or record_id is None:
            return
        try:
            current = controller.view(record_id)
        except BrokerError as error:
            self._handle_broker_error(error)
            return
        dialog = CredentialEditorDialog(self, existing=current)

        if dialog.exec() != dialog.DialogCode.Accepted or dialog.credential is None:
            return
        try:
            updated = controller.edit(record_id, dialog.credential)
        except BrokerError as error:
            self._handle_broker_error(error)
            return
        self._refresh_entries(updated.record_id)
        self.statusBar().showMessage("Credential updated after approval.", 7_000)

    def _copy_password(self) -> None:
        controller = self._controller
        record_id = self._selected_record_id()

        if controller is None or record_id is None:
            return

        try:
            controller.copy_password(record_id)

        except BrokerError as error:
            self._handle_broker_error(error)
            return
        self.statusBar().showMessage(
            "Password copied. It will clear after 30 seconds if unchanged.",
            10_000,
        )

    def _reveal_password(self) -> None:
        controller = self._controller
        record_id = self._selected_record_id()

        if controller is None or record_id is None:
            return

        try:
            password = controller.reveal_password(record_id)

        except BrokerError as error:
            self._handle_broker_error(error)
            return
        PasswordRevealDialog(password, self).exec()
        password = ""

    def _delete_credential(self) -> None:
        controller = self._controller
        record_id = self._selected_record_id()

        if controller is None or record_id is None:
            return
        title_item = self._table.item(self._table.currentRow(), 0)
        title = "this credential" if title_item is None else f"“{title_item.text()}”"
        choice = QMessageBox.question(
            self,
            "Delete credential",
            f"Delete {title}? Windows Hello will ask you to confirm.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )

        if choice != QMessageBox.StandardButton.Yes:
            return
        try:
            controller.delete(record_id)
        except BrokerError as error:
            self._handle_broker_error(error)
            return
        self._refresh_entries()
        self.statusBar().showMessage("Credential deleted after approval.", 7_000)

    def _create_encrypted_backup(self) -> None:
        controller = self._controller
        vault_path = self._vault_path

        if controller is None or vault_path is None:
            return
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        suggested = Path.home() / f"{vault_path.stem}-backup-{timestamp}.pmvault-backup"
        selected, _filter = QFileDialog.getSaveFileName(
            self,
            "Create verified encrypted backup",
            str(suggested),
            BACKUP_FILTER,
            options=_NEW_FILE_DIALOG_OPTIONS,
        )

        if not selected:
            return
        destination = Path(selected)

        if not destination.suffix:
            destination = destination.with_suffix(".pmvault-backup")

        if destination.exists():
            QMessageBox.warning(
                self,
                "Choose a new file",
                "Backup never overwrites a file. Choose a new destination name.",
            )

            return
        if not self._confirm_cloud_location(destination, "The backup destination"):
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

        try:
            controller.create_backup(str(destination.expanduser().absolute()))
        except BrokerError as error:
            self._handle_broker_error(error)
            return

        finally:
            QApplication.restoreOverrideCursor()
        self._audit_event("backup_created")
        QMessageBox.information(
            self,
            "Encrypted backup created",
            "Your encrypted backup is ready. It uses the same "
            "master passphrase as the open vault and no existing file was overwritten.",
        )

        self.statusBar().showMessage("Encrypted backup created and verified.", 10_000)

    def _show_settings(self) -> None:
        dialog = SettingsDialog(
            self._auto_lock_minutes,
            self._audit is not None,
            self,
        )

        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        self._auto_lock_minutes = dialog.auto_lock_minutes
        self._settings.setValue(AUTO_LOCK_SETTING, self._auto_lock_minutes)
        self._settings.sync()
        self._activity_guard.set_timeout_seconds(self._auto_lock_minutes * 60)
        self._activity_guard.mark_activity()
        self.statusBar().showMessage("Automatic-lock setting saved.", 7_000)

    def _handle_broker_error(self, error: BrokerError) -> None:

        if isinstance(error, BrokerDeniedError):
            QMessageBox.information(
                self,
                "Action not approved",
                "The action was not approved or its permission expired. Try again to confirm.",
            )
            return
        QMessageBox.critical(
            self,
            "Vault locked",
            "The vault has been locked because its connection was interrupted.",
        )
        self._lock_vault()

    def _lock_vault(self) -> None:
        self._perform_lock("Vault locked. No vault is open.", "vault_locked_manual")

    def _emergency_lock(self) -> None:
        if self._controller is None:
            return
        self._perform_lock(
            "Emergency shortcut activated. Vault locked.",
            "vault_locked_emergency",
        )

    def _perform_lock(self, status_message: str, audit_event: str) -> None:

        broker = self._broker
        was_unlocked = broker is not None
        self._broker = None
        self._controller = None
        self._vault_path = None
        self._search_timer.stop()
        self._search.clear()
        self._table.setRowCount(0)
        for dialog in self.findChildren(QDialog):
            dialog.reject()

        if broker is not None:
            broker.close()

        if was_unlocked:
            self._audit_event(audit_event)
        self._pages.setCurrentWidget(self._welcome_page)
        self._update_action_state()
        self.statusBar().showMessage(status_message, 10_000)

    def closeEvent(self, event: QCloseEvent) -> None:
        application = QApplication.instance()

        if application is not None:
            application.removeEventFilter(self)

        if self._session_notifications_registered:
            unregister_session_notifications(int(self.winId()))
            self._session_notifications_registered = False
        self._security_timer.stop()
        self._lock_vault()
        self._audit_event("application_closed")
        event.accept()
