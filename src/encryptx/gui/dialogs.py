"""
gui/dialogs.py - the compact, tall windows opened from the Explorer right-click menu.

    ActionDialog     "Encrypt" and "Decrypt"   (sources are already chosen: no drag & drop)
    ChecksumDialog   hash box on top, one row per algorithm, the matching one turns green

Several selected files arrive in the SAME window (see platform/single_instance.py).
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, List

from PySide6.QtCore import QTimer, QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLayout, QLineEdit, QScrollArea,
                               QVBoxLayout, QWidget)

from ..core import file_operations as ops
from . import styles as ui
from .forms import DecryptForm, EncryptForm
from .jobs import JobController, JobRunner, run_checksum
from .widgets import (BaseWindow, Button, Dots, HashField, SourceList, StatusProgress,
                      separator)

CONTEXT_FLAGS = (Qt.Window | Qt.WindowTitleHint | Qt.WindowSystemMenuHint
                 | Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)


def reveal_in_folder(path: str) -> None:
    if os.name == "nt":
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
    else:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).parent)))


# ----------------------------------------------------------------------------
# Encrypt / Decrypt
# ----------------------------------------------------------------------------
class ActionDialog(BaseWindow):
    def __init__(self, mode: str, paths=()):
        self.form = EncryptForm(wide=False) if mode == "encrypt" else DecryptForm(wide=False)
        super().__init__(f"{self.form.ACTION} - EncryptX", CONTEXT_FLAGS)
        self._last_output = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)
        root.setSizeConstraint(QLayout.SetFixedSize)         # compact: the size follows the content

        self.sources = SourceList(compact=True)
        self.sources.setMinimumWidth(440)
        root.addWidget(self.sources)
        root.addWidget(self.form)

        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        self.status = StatusProgress()
        self.folder_button = Button(icon="folder", tooltip="Show in folder")
        self.folder_button.clicked.connect(lambda: reveal_in_folder(self._last_output))
        self.folder_button.hide()
        self.main_button = Button(self.form.ACTION, primary=True)
        self.main_button.setFixedWidth(96)
        close = Button("Close")
        close.setFixedWidth(76)
        close.clicked.connect(self.close)
        for widget, stretch in ((self.status, 1), (self.folder_button, 0),
                                (self.main_button, 0), (close, 0)):
            bottom.addWidget(widget, stretch)
        root.addLayout(bottom)

        self.controller = JobController(self.sources, self.status, self.main_button, self)
        self.controller.outcome.connect(self._on_outcome)
        self.main_button.clicked.connect(lambda: self.controller.toggle(self.form))
        self.add_paths(paths)

    def add_paths(self, paths) -> None:
        if not self.controller.running:
            self.sources.add_paths(paths)

    def _on_outcome(self, _row: int, outcome) -> None:
        data = outcome.data or {}
        if data.get("path"):
            self._last_output = data["path"]
            self.folder_button.show()
        if data.get("digest") and hasattr(self.form, "set_digest"):
            self.form.set_digest(data["alg"], data["digest"])

    def closeEvent(self, event) -> None:
        self.controller.shutdown()
        super().closeEvent(event)


# ----------------------------------------------------------------------------
# Checksum
# ----------------------------------------------------------------------------
class _Section:
    """The widgets of ONE source (title + one row per algorithm)."""

    def __init__(self, path: str):
        self.path = path
        self.digests: Dict[str, str] = {}
        self.fields: Dict[str, HashField] = {}
        self.widget = QWidget()
        self.layout = QVBoxLayout(self.widget)
        self.layout.setContentsMargins(0, 0, 0, 6)
        self.layout.setSpacing(7)
        self.title = QLabel(os.path.basename(path) or path)
        self.title.setObjectName("title")
        self.title.setToolTip(path)
        self.note = QLabel("Waiting...")
        self.note.setObjectName("dim")
        self.layout.addWidget(self.title)
        self.layout.addWidget(self.note)


class ChecksumDialog(BaseWindow):
    def __init__(self, paths=()):
        super().__init__("Checksum - EncryptX", CONTEXT_FLAGS | Qt.WindowMaximizeButtonHint)
        self._sections: Dict[str, _Section] = {}
        self._queue: List[str] = []
        self._batch: List[str] = []
        self._runner = None
        self._scrolled_to = None

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(8)

        self.compare = QLineEdit()
        self.compare.setPlaceholderText("Enter your checksum to compare...")
        self.compare.setClearButtonEnabled(True)
        self.compare.textChanged.connect(self.refresh_matches)
        root.addWidget(self.compare)
        self.verdict = QLabel("")
        self.verdict.setFixedHeight(20)
        root.addWidget(self.verdict)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        holder = QWidget()
        self.rows = QVBoxLayout(holder)
        self.rows.setContentsMargins(0, 0, 6, 0)
        self.rows.setSpacing(8)
        self.rows.addStretch(1)
        self.scroll.setWidget(holder)
        root.addWidget(self.scroll, 1)

        root.addWidget(separator())
        bottom = QHBoxLayout()
        bottom.setSpacing(10)
        self.dots = Dots()
        self.dots.hide()
        self.info = QLabel("")
        self.info.setObjectName("dim")
        close = Button("Close")
        close.setFixedWidth(84)
        close.clicked.connect(self.close)
        bottom.addWidget(self.dots)
        bottom.addWidget(self.info, 1)
        bottom.addWidget(close)
        root.addLayout(bottom)

        self.setMinimumSize(480, 420)
        self.setMaximumSize(900, 780)
        self.resize(540, 580)
        self.add_paths(paths)

    # -- sources -------------------------------------------------------------
    def add_paths(self, paths) -> None:
        for path in paths:
            path = os.path.normpath(str(path))
            if path in self._sections or not os.path.exists(path):
                continue
            section = _Section(path)
            self._sections[path] = section
            self.rows.insertWidget(self.rows.count() - 1, section.widget)
            self._queue.append(path)
        self._pump()

    def _pump(self) -> None:
        if self._runner is not None or not self._queue:
            return
        self._batch, self._queue = self._queue, []
        self._runner = JobRunner(run_checksum, self._batch, None, self)
        self._runner.item_started.connect(
            lambda i: self._sections[self._batch[i]].note.setText("Calculating..."))
        self._runner.progress.connect(self._on_progress)
        self._runner.item_done.connect(self._on_item)
        self._runner.all_done.connect(self._on_all_done)
        self.dots.start()
        self._runner.start()

    def _on_progress(self, index: int, count: int, fraction: float, _total: int) -> None:
        text = f"Calculating {int((index + fraction) / count * 100)}%"
        self.info.setText(text + (f" · {index + 1}/{count}" if count > 1 else ""))

    def _on_item(self, index: int, outcome) -> None:
        section = self._sections[self._batch[index]]
        if not outcome.ok:
            section.note.setText(outcome.text)
            section.note.setStyleSheet(f"color: {ui.ERROR};")
            return
        section.note.hide()
        section.digests = outcome.data["digests"]
        for algorithm, digest in section.digests.items():
            row = QHBoxLayout()
            row.setSpacing(10)
            name = QLabel(algorithm + ":")
            name.setMinimumWidth(78)
            field = HashField(digest)
            field.copied.connect(lambda _v: self.info.setText("Hash copied to the clipboard"))
            section.fields[algorithm] = field
            row.addWidget(name)
            row.addWidget(field, 1)
            section.layout.addLayout(row)
        self.refresh_matches()

    def _on_all_done(self, cancelled: bool) -> None:
        self._runner = None
        if self._queue:
            return self._pump()
        self.dots.stop()
        done = sum(1 for s in self._sections.values() if s.digests)
        self.info.setText(f"Done · {done} item{'s' if done != 1 else ''}")
        self.refresh_matches()

    # -- comparing -----------------------------------------------------------
    def refresh_matches(self) -> None:
        text = self.compare.text().strip()
        hits, first = [], None
        for section in self._sections.values():
            matched = ops.matching_algorithms(section.digests, text) if text else []
            for algorithm, field in section.fields.items():
                field.set_matched(algorithm in matched)
            for algorithm in matched:
                hits.append(algorithm if len(self._sections) == 1
                            else f"{algorithm} ({os.path.basename(section.path)})")
                first = first or section.fields[algorithm]

        finished = self._runner is None and not self._queue
        if not text or (not hits and not finished):
            self.verdict.setText("")
        elif hits:
            self.verdict.setText("✓  Match: " + ", ".join(hits))
            self.verdict.setStyleSheet(f"color: {ui.OK}; font-weight: 600;")
        else:
            self.verdict.setText("✗  No match")
            self.verdict.setStyleSheet(f"color: {ui.ERROR}; font-weight: 600;")

        if first is not None and first is not self._scrolled_to:     # bring the right one into view
            QTimer.singleShot(0, lambda f=first: self.scroll.ensureWidgetVisible(f, 0, 80))
        self._scrolled_to = first

    def closeEvent(self, event) -> None:
        if self._runner is not None:
            self._runner.cancel()
            self._runner.wait(5000)
        super().closeEvent(event)
