"""
app.py - entry point.

    EncryptX.exe                         big window (Encrypt / Decrypt tabs, drag & drop)
    EncryptX.exe encrypt  "<path>" ...   compact Encrypt window   (Explorer menu)
    EncryptX.exe decrypt  "<path>" ...   compact Decrypt window
    EncryptX.exe checksum "<path>" ...   compact Checksum window
    EncryptX.exe install-menu | uninstall-menu    (development only; the installer does it)
"""

import ctypes
import os
import sys

USAGE = ("EncryptX\n\n  encrypt  <path>\n  decrypt  <path.encx>\n  checksum <path>\n"
         "  install-menu | uninstall-menu")
COLLECT_MS = 300        # wait this long so several selected files land in ONE window


def _set_app_id() -> None:
    """Own taskbar identity (so the taskbar shows the EncryptX icon, not python's)."""
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("EncryptX.App")
    except Exception:
        pass


def _context_window(command: str, paths: list):
    """Compact window for the right-click menu; returns the window or None (= exit)."""
    from PySide6.QtCore import QTimer
    from .gui.dialogs import ActionDialog, ChecksumDialog
    from .platform.single_instance import SingleInstance

    instance = SingleInstance(f"EncryptX-{command}")
    if not instance.claim(paths):
        return None                                   # another window got our file
    collected = list(paths)
    holder = {}

    def show() -> None:
        window = (ChecksumDialog(collected) if command == "checksum"
                  else ActionDialog(command, collected))
        instance.paths_received.disconnect()
        instance.paths_received.connect(window.add_paths)
        window.show()
        holder["window"] = window

    instance.paths_received.connect(collected.extend)
    QTimer.singleShot(COLLECT_MS, show)
    holder["instance"] = instance                     # keep the server alive
    return holder


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0].lower() if argv else ""

    if command in ("install-menu", "uninstall-menu"):          # no GUI needed
        from .platform import windows_context_menu as menu
        (menu.install if command == "install-menu" else menu.uninstall)()
        return 0

    _set_app_id()
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication, QMessageBox
    from .gui import styles

    app = QApplication(sys.argv[:1])
    app.setApplicationName("EncryptX")
    app.setWindowIcon(QIcon(str(styles.asset("icon.png"))))
    styles.apply_theme(app)

    if not command:
        from .gui.main_window import MainWindow
        window = MainWindow()
        window.show()
    elif command in ("encrypt", "decrypt", "checksum"):
        window = _context_window(command, argv[1:])
        if window is None:
            return 0
    else:
        QMessageBox.information(None, "EncryptX", USAGE)
        return 2
    code = app.exec()
    for widget in app.topLevelWidgets():              # tidy shutdown (threads, windows)
        widget.deleteLater()
    app.processEvents()
    return code


if __name__ == "__main__":
    sys.exit(main())
