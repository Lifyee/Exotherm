"""
Exotherm - Secure File Encryptor GUI
=====================================
A modern drag-and-drop desktop GUI, built with PySide6, for the Argon2 +
AES-GCM file encryption backend.
"""

import os
import sys
from exotherm.backend_tieup import BatchResult, process_path, suffix

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QFrame
)

ENCRYPTED_SUFFIX = suffix

app_state = {"selected_item_path": None, "worker": None, "busy": False, "window": None}


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

class FileOperationWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, path, password_text, action):
        super().__init__()
        self.path = path
        self.password = password_text.encode("utf-8")
        self.action = action

    def run(self):
        try:
            self.completed.emit(process_path(self.path, self.password, self.action))
        except Exception as error:
            self.failed.emit(str(error) or error.__class__.__name__)
        finally:
            # Drop the password copy as soon as the worker exits.
            self.password = b""


# ---------------------------------------------------------------------------
# Visual Styling
# ---------------------------------------------------------------------------

WINDOW_STYLE = """
QWidget {
    background-color: #1b1e27;
    color: #e6e6ea;
    font-family: "Montserrat", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}
QLabel#titleLabel {
    font-size: 22px;
    font-weight: 700;
    color: #7c8cff;
}
QLabel#subtitleLabel {
    font-size: 12px;
    color: #8b8fa3;
}
QLabel#fieldLabel {
    font-size: 12px;
    font-weight: 600;
    color: #b7bad0;
    margin-top: 6px;
}
QLineEdit {
    background-color: #262a37;
    border: 1px solid #383d4f;
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 13px;
    color: #ffffff;
}
QLineEdit:focus {
    border: 1px solid #7c8cff;
}
QPushButton#toggleButton {
    background-color: #262a37;
    border: 1px solid #383d4f;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}
QPushButton#toggleButton:hover {
    border: 1px solid #7c8cff;
}
QPushButton#encryptButton {
    background-color: #4dd28c;
    color: #0d1a12;
    border: none;
    border-radius: 10px;
    padding: 12px;
    font-size: 14px;
    font-weight: 700;
}
QPushButton#encryptButton:disabled {
    background-color: #2b3630;
    color: #6a7a70;
}
QPushButton#encryptButton:hover:!disabled {
    background-color: #63dc9d;
}
QPushButton#decryptButton {
    background-color: #7c8cff;
    color: #0d0f1a;
    border: none;
    border-radius: 10px;
    padding: 12px;
    font-size: 14px;
    font-weight: 700;
}
QPushButton#decryptButton:disabled {
    background-color: #2b2e3d;
    color: #6a6e85;
}
QPushButton#decryptButton:hover:!disabled {
    background-color: #94a1ff;
}
"""

DROP_ZONE_STYLE_IDLE = """
QFrame#dropZone {
    background-color: #20242f;
    border: 2px dashed #3d4258;
    border-radius: 14px;
}
"""

DROP_ZONE_STYLE_ACTIVE = """
QFrame#dropZone {
    background-color: #232a3d;
    border: 2px dashed #7c8cff;
    border-radius: 14px;
}
"""


# ---------------------------------------------------------------------------
# User Interface Functions
# ---------------------------------------------------------------------------

def update_status(status_label, text_message, is_it_an_error):
    status_label.setText(text_message)
    text_color = "#ff6b6b" if is_it_an_error else "#4dd28c"
    status_label.setStyleSheet(f"color: {text_color}; font-size: 12px;")


def update_buttons_state(password_input, encrypt_button, decrypt_button):
    file_is_selected = app_state["selected_item_path"] is not None
    password_is_typed = len(password_input.text()) > 0
    encrypt_button.setEnabled(file_is_selected and password_is_typed)
    decrypt_button.setEnabled(file_is_selected and password_is_typed)


def display_selected_item(item_path, drop_zone_label, drop_zone_hint, status_label,
                          password_input, encrypt_button, decrypt_button):
    app_state["selected_item_path"] = item_path
    icon_symbol = "📁" if os.path.isdir(item_path) else "📄"
    file_name = os.path.basename(item_path)
    drop_zone_label.setText(f"{icon_symbol}  {file_name}")
    drop_zone_hint.setText(item_path)
    update_status(status_label, "Item selected. Enter a password to begin.", is_it_an_error=False)
    update_buttons_state(password_input, encrypt_button, decrypt_button)


def open_file_browser(drop_zone_label, drop_zone_hint, status_label,
                      password_input, encrypt_button, decrypt_button):
    message_box = QMessageBox()
    message_box.setWindowTitle("Choose Type")
    message_box.setText("Do you want to select a file or a folder?")
    message_box.setStyleSheet(WINDOW_STYLE)

    file_choice = message_box.addButton("File", QMessageBox.ButtonRole.ActionRole)
    folder_choice = message_box.addButton("Folder", QMessageBox.ButtonRole.ActionRole)
    message_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)

    message_box.exec()
    chosen_path = None

    if message_box.clickedButton() == file_choice:
        chosen_path, _ = QFileDialog.getOpenFileName(None, "Choose a file")
    elif message_box.clickedButton() == folder_choice:
        chosen_path = QFileDialog.getExistingDirectory(None, "Choose a folder")

    if chosen_path:
        display_selected_item(chosen_path, drop_zone_label, drop_zone_hint, status_label,
                              password_input, encrypt_button, decrypt_button)


def switch_password_view(password_input, toggle_button):
    if password_input.echoMode() == QLineEdit.EchoMode.Password:
        password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        toggle_button.setText("Hide")
    else:
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        toggle_button.setText("Show")


def start_encryption(drop_zone_label, drop_zone_hint, password_input, status_label,
                     encrypt_button, decrypt_button):
    _start_operation("encrypt", drop_zone_label, drop_zone_hint, password_input,
                     status_label, encrypt_button, decrypt_button)


def start_decryption(drop_zone_label, drop_zone_hint, password_input, status_label,
                     encrypt_button, decrypt_button):
    _start_operation("decrypt", drop_zone_label, drop_zone_hint, password_input,
                     status_label, encrypt_button, decrypt_button)


def _start_operation(action, drop_zone_label, drop_zone_hint, password_input,
                     status_label, encrypt_button, decrypt_button):
    selected_path = app_state["selected_item_path"]
    password_text = password_input.text()
    if app_state["busy"] or not selected_path or not password_text:
        return

    app_state["busy"] = True
    encrypt_button.setEnabled(False)
    decrypt_button.setEnabled(False)
    password_input.setEnabled(False)
    verb = "Encrypting" if action == "encrypt" else "Decrypting"
    update_status(status_label,
                  f"{verb}… Do not close Exotherm until this finishes; closing may damage files.",
                  is_it_an_error=False)

    worker = FileOperationWorker(selected_path, password_text, action)
    app_state["worker"] = worker
    worker.completed.connect(
        lambda result: _complete_operation(result, drop_zone_label, drop_zone_hint,
                                           password_input, status_label,
                                           encrypt_button, decrypt_button)
    )
    worker.failed.connect(
        lambda message: _fail_operation(action, message, password_input, status_label,
                                        encrypt_button, decrypt_button)
    )
    worker.finished.connect(worker.deleteLater)
    worker.finished.connect(lambda current=worker: _release_worker(current))
    worker.start()


def _release_worker(worker):
    if app_state["worker"] is worker:
        app_state["worker"] = None


def _complete_operation(result: BatchResult, drop_zone_label, drop_zone_hint,
                        password_input, status_label, encrypt_button, decrypt_button):
    app_state["busy"] = False
    password_input.setEnabled(True)
    update_buttons_state(password_input, encrypt_button, decrypt_button)
    action_name = "Encryption" if result.action == "encrypt" else "Decryption"

    if result.succeeded:
        password_input.clear()
        if os.path.isfile(app_state["selected_item_path"]):
            output_path = next((item.output_path for item in result.outcomes
                                if item.status == "success"), None)
            if output_path:
                display_selected_item(output_path, drop_zone_label, drop_zone_hint,
                                      status_label, password_input,
                                      encrypt_button, decrypt_button)
                password_input.clear()

    if result.action == "decrypt" and result.candidates and result.succeeded == 0 \
            and result.wrong_password_or_corrupt:
        QMessageBox.warning(None, "Password Not Accepted",
                            "The password did not decrypt any encrypted files. "
                            "The matching files were left unchanged.")
        update_status(status_label, "No files were decrypted; the password may be incorrect.", True)
        return

    if result.succeeded == 0 and result.candidates == 0 and result.failed == 0:
        message = "No normal files were found to encrypt." if result.action == "encrypt" \
            else "No encrypted .exotherm files were found."
        QMessageBox.information(None, "Nothing to Process", message)
        update_status(status_label, message, False)
        return

    summary = f"{action_name}: {result.succeeded} succeeded, {result.skipped} skipped, {result.failed} failed."
    if result.action == "decrypt" and result.wrong_password_or_corrupt:
        summary += (f" {result.wrong_password_or_corrupt} encrypted file(s) did not match "
                    "the password (or were damaged) and were left unchanged.")
    failures = [item for item in result.outcomes if item.status == "failed"]
    if failures:
        summary += "\n\nSome files could not be processed: " + "; ".join(
            f"{os.path.basename(item.path)}: {item.message}" for item in failures[:4]
        )
        if len(failures) > 4:
            summary += f"; and {len(failures) - 4} more."
    if result.failed or result.skipped or result.wrong_password_or_corrupt:
        QMessageBox.warning(None, f"{action_name} Finished", summary)
        update_status(status_label, summary.split("\n", 1)[0], True)
    else:
        QMessageBox.information(None, f"{action_name} Finished", summary)
        update_status(status_label, summary.split("\n", 1)[0], False)


def _fail_operation(action, message, password_input, status_label,
                    encrypt_button, decrypt_button):
    app_state["busy"] = False
    password_input.setEnabled(True)
    update_buttons_state(password_input, encrypt_button, decrypt_button)
    QMessageBox.critical(None, "Error", f"Failed to {action}: {message}")
    update_status(status_label, f"{action.title()} failed.", True)


# ---------------------------------------------------------------------------
# Mouse and Drag Events
# ---------------------------------------------------------------------------

def setup_drag_enter(drop_zone_frame):
    def event_handler(event):
        if event.mimeData().hasUrls():
            drop_zone_frame.setStyleSheet(DROP_ZONE_STYLE_ACTIVE)
            event.acceptProposedAction()
        else:
            event.ignore()

    return event_handler


def setup_drag_leave(drop_zone_frame):
    def event_handler(event):
        drop_zone_frame.setStyleSheet(DROP_ZONE_STYLE_IDLE)

    return event_handler


def setup_drop_item(drop_zone_frame, drop_zone_label, drop_zone_hint, status_label,
                    password_input, encrypt_button, decrypt_button):
    def event_handler(event):
        drop_zone_frame.setStyleSheet(DROP_ZONE_STYLE_IDLE)
        item_links = event.mimeData().urls()
        if not item_links:
            return

        found_path = item_links[0].toLocalFile()
        if not os.path.exists(found_path):
            update_status(status_label, "The dropped item does not exist.", is_it_an_error=True)
            return

        display_selected_item(found_path, drop_zone_label, drop_zone_hint, status_label,
                              password_input, encrypt_button, decrypt_button)
        event.acceptProposedAction()

    return event_handler


def setup_mouse_click(drop_zone_label, drop_zone_hint, status_label,
                      password_input, encrypt_button, decrypt_button):
    def event_handler(event):
        open_file_browser(drop_zone_label, drop_zone_hint, status_label,
                          password_input, encrypt_button, decrypt_button)

    return event_handler


# ---------------------------------------------------------------------------
# Window Setup
# ---------------------------------------------------------------------------

class ExothermWindow(QWidget):
    def closeEvent(self, event):
        if app_state["busy"]:
            QMessageBox.warning(
                self, "Operation in Progress",
                "Exotherm is still processing files. Do not close the program; "
                "interrupting file operations may damage your files."
            )
            event.ignore()
        else:
            event.accept()


def create_main_window():
    main_window = ExothermWindow()
    main_window.setWindowTitle("Exotherm")
    main_window.setFixedSize(460, 560)
    main_window.setStyleSheet(WINDOW_STYLE)

    app_state["window"] = main_window

    main_layout = QVBoxLayout(main_window)
    main_layout.setContentsMargins(28, 28, 28, 24)
    main_layout.setSpacing(6)

    app_title = QLabel("Exotherm")
    app_title.setObjectName("titleLabel")
    app_subtitle = QLabel("Argon2 key derivation + AES-GCM encryption")
    app_subtitle.setObjectName("subtitleLabel")
    main_layout.addWidget(app_title)
    main_layout.addWidget(app_subtitle)
    main_layout.addSpacing(18)

    drop_area = QFrame()
    drop_area.setObjectName("dropZone")
    drop_area.setStyleSheet(DROP_ZONE_STYLE_IDLE)
    drop_area.setMinimumHeight(160)
    drop_area.setCursor(Qt.CursorShape.PointingHandCursor)
    drop_area.setAcceptDrops(True)

    drop_layout = QVBoxLayout(drop_area)
    drop_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    drop_layout.setSpacing(6)

    drop_main_text = QLabel("Drag & drop a file or folder here")
    drop_main_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
    drop_main_text.setStyleSheet("background-color: transparent; font-size: 14px; font-weight: 600; color: #e6e6ea;")

    drop_sub_text = QLabel("or click to browse")
    drop_sub_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
    drop_sub_text.setWordWrap(True)
    drop_sub_text.setStyleSheet("background-color: transparent; font-size: 11px; color: #8b8fa3;")

    drop_layout.addWidget(drop_main_text)
    drop_layout.addWidget(drop_sub_text)
    main_layout.addWidget(drop_area)
    main_layout.addSpacing(16)

    password_text_label = QLabel("Password")
    password_text_label.setObjectName("fieldLabel")
    main_layout.addWidget(password_text_label)

    password_layout = QHBoxLayout()
    password_box = QLineEdit()
    password_box.setEchoMode(QLineEdit.EchoMode.Password)
    password_box.setPlaceholderText("Enter a password")

    visibility_button = QPushButton("Show")
    visibility_button.setObjectName("toggleButton")
    visibility_button.setCursor(Qt.CursorShape.PointingHandCursor)

    password_layout.addWidget(password_box)
    password_layout.addWidget(visibility_button)
    main_layout.addLayout(password_layout)
    main_layout.addSpacing(20)

    buttons_layout = QHBoxLayout()
    buttons_layout.setSpacing(12)

    encrypt_btn = QPushButton("Encrypt File")
    encrypt_btn.setObjectName("encryptButton")
    encrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    encrypt_btn.setEnabled(False)

    decrypt_btn = QPushButton("Decrypt File")
    decrypt_btn.setObjectName("decryptButton")
    decrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    decrypt_btn.setEnabled(False)

    buttons_layout.addWidget(encrypt_btn)
    buttons_layout.addWidget(decrypt_btn)
    main_layout.addLayout(buttons_layout)
    main_layout.addSpacing(14)

    info_label = QLabel("Drop or browse for a file or folder to get started.")
    info_label.setWordWrap(True)
    info_label.setStyleSheet("color: #8b8fa3; font-size: 12px;")
    main_layout.addWidget(info_label)
    main_layout.addStretch(1)

    drop_area.dragEnterEvent = setup_drag_enter(drop_area)
    drop_area.dragLeaveEvent = setup_drag_leave(drop_area)
    drop_area.dropEvent = setup_drop_item(
        drop_area, drop_main_text, drop_sub_text, info_label,
        password_box, encrypt_btn, decrypt_btn
    )
    drop_area.mousePressEvent = setup_mouse_click(
        drop_main_text, drop_sub_text, info_label,
        password_box, encrypt_btn, decrypt_btn
    )

    visibility_button.clicked.connect(
        lambda: switch_password_view(password_box, visibility_button)
    )
    password_box.textChanged.connect(
        lambda _: update_buttons_state(password_box, encrypt_btn, decrypt_btn)
    )
    encrypt_btn.clicked.connect(
        lambda: start_encryption(drop_main_text, drop_sub_text, password_box, info_label,
                                 encrypt_btn, decrypt_btn)
    )
    decrypt_btn.clicked.connect(
        lambda: start_decryption(drop_main_text, drop_sub_text, password_box, info_label,
                                 encrypt_btn, decrypt_btn)
    )

    return main_window

def launch_app():
    app_instance = QApplication(sys.argv)
    window_instance = create_main_window()
    window_instance.show()
    sys.exit(app_instance.exec())

if __name__ == "__main__":
    launch_app()
