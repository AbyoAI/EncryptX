"""
gui/main_window.py - the window that opens when you start EncryptX.exe.

    Tabs:  Encrypt | Decrypt        (checksum lives in the right-click menu)
    Drag & drop files/folders, or use  +  /  -  next to the list.

The right-click menu uses the compact windows in dialogs.py instead.
"""

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMenu, QStackedWidget,
                               QVBoxLayout, QWidget)

from . import styles as ui
from .forms import DecryptForm, EncryptForm
from .jobs import JobController
from .widgets import BaseWindow, Button, SourceList, StatusProgress, TabBar, separator

MIN_SIZE = (680, 600)        # smaller than this would hide controls
MAX_SIZE = (980, 820)        # bigger than this only stretches the layout


class MainWindow(BaseWindow):
    def __init__(self, paths=(), tab: int = 0):
        super().__init__("EncryptX")
        self.forms = [EncryptForm(wide=True), DecryptForm(wide=True)]

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- header: tabs + logo
        header = QHBoxLayout()
        header.setContentsMargins(10, 4, 16, 0)
        self.tabs = TabBar(["Encrypt", "Decrypt"])
        header.addWidget(self.tabs, 1)
        logo = QLabel()
        pixmap = QPixmap(str(ui.asset("icon.png"))).scaled(
            52, 52, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        pixmap.setDevicePixelRatio(2.0)
        logo.setPixmap(pixmap)
        header.addWidget(logo)
        root.addLayout(header)
        root.addWidget(separator())

        # -- sources
        body = QVBoxLayout()
        body.setContentsMargins(16, 12, 16, 0)
        body.setSpacing(10)
        title = QLabel("Sources")
        title.setObjectName("dim")
        body.addWidget(title)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.sources = SourceList(accept_drops=True)
        self.sources.setMinimumHeight(130)
        self.sources.paths_dropped.connect(self.add_paths)
        row.addWidget(self.sources, 1)
        buttons = QVBoxLayout()
        buttons.setSpacing(6)
        self.add_button = Button(icon="plus", tooltip="Add files or a folder")
        self.add_button.clicked.connect(self._add_menu)
        self.remove_button = Button(icon="minus", tooltip="Remove the selected items")
        self.remove_button.clicked.connect(self.sources.remove_selected)
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        buttons.addStretch(1)
        row.addLayout(buttons)
        body.addLayout(row, 1)
        body.addWidget(separator())

        # -- options (one page per tab)
        self.stack = QStackedWidget()
        for form in self.forms:
            self.stack.addWidget(form)
        body.addWidget(self.stack)
        root.addLayout(body, 1)

        # -- bottom: progress + buttons
        bottom = QHBoxLayout()
        bottom.setContentsMargins(16, 14, 16, 16)
        bottom.setSpacing(8)
        self.status = StatusProgress()
        self.main_button = Button("Encrypt", primary=True)
        self.main_button.setFixedWidth(104)
        close = Button("Close")
        close.setFixedWidth(84)
        close.clicked.connect(self.close)
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.main_button)
        bottom.addWidget(close)
        root.addLayout(bottom)

        self.controller = JobController(self.sources, self.status, self.main_button, self)
        self.main_button.clicked.connect(lambda: self.controller.toggle(self.current_form()))
        self.tabs.changed.connect(self._on_tab)

        self.setMinimumSize(*MIN_SIZE)
        self.setMaximumSize(*MAX_SIZE)
        self.resize(MIN_SIZE[0] + 60, max(self.sizeHint().height(), MIN_SIZE[1]))
        self.add_paths(paths)
        if tab:
            self.tabs.select(tab)

    def current_form(self):
        return self.forms[self.stack.currentIndex()]

    def _on_tab(self, index: int) -> None:
        if self.controller.running:                     # cannot switch while working
            self.tabs.select(self.stack.currentIndex(), notify=False)
            return
        self.stack.setCurrentIndex(index)
        self.main_button.setText(self.current_form().ACTION)
        self.sources.clear_status()
        self.status.reset()

    def add_paths(self, paths) -> None:
        if not self.controller.running:
            self.sources.add_paths(paths)

    def _add_menu(self) -> None:
        menu = QMenu(self)
        menu.addAction("Add files...", self._add_files)
        menu.addAction("Add folder...", self._add_folder)
        menu.exec(self.add_button.mapToGlobal(self.add_button.rect().bottomLeft()))

    def _add_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Add files")
        self.add_paths(files)

    def _add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Add folder")
        if folder:
            self.add_paths([folder])

    def closeEvent(self, event) -> None:
        self.controller.shutdown()
        super().closeEvent(event)
