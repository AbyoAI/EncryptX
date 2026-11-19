"""
gui/jobs.py - runs the work in a background thread and keeps the window in sync.

    run_encrypt / run_decrypt / run_checksum   plain functions (no Qt inside)
    JobRunner      QThread that walks the sources one by one and emits signals
    JobController  shared by the main window and the right-click dialogs:
                   Start/Cancel button, per-row status, progress text

Rule: the thread only gets plain values (paths, settings). It never touches a widget.
"""

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, QThread, Signal

from ..core import file_operations as ops


@dataclass
class Outcome:
    ok: bool
    text: str
    data: Optional[dict] = None


@dataclass
class EncryptSettings:
    out_dir: str
    password: str
    algo: str
    kdf: str
    checksum: str            # algorithm name, "" = off
    compress: bool
    hide_name: bool
    delete_source: bool


@dataclass
class DecryptSettings:
    out_dir: str
    password: str
    delete_source: bool


def format_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ----------------------------------------------------------------------------
# The three jobs (run in the worker thread)
# ----------------------------------------------------------------------------
def run_encrypt(path: str, s: EncryptSettings, progress, cancel) -> Outcome:
    found = {}
    out = ops.encrypt_path(
        path, s.out_dir or str(Path(path).parent), s.password, s.algo, s.kdf, s.compress,
        s.hide_name, s.checksum or None, progress, cancel,
        on_checksum=lambda alg, digest: found.update(alg=alg, digest=digest))
    if s.delete_source:
        ops.delete_path(path)
    text = "Encrypted"
    if found:
        text += f" · {found['alg']} {found['digest'][:8]}…"
    return Outcome(True, text, {"path": out, **found})


def run_decrypt(path: str, s: DecryptSettings, progress, cancel) -> Outcome:
    result = ops.decrypt_path(path, s.out_dir or str(Path(path).parent), s.password,
                              progress, cancel)
    if result.checksum == "mismatch":                       # keep the encrypted file!
        return Outcome(False, f"Checksum MISMATCH ({result.algorithm})", {"path": result.path})
    if s.delete_source:
        ops.delete_path(path)
    text = "Decrypted"
    if result.checksum == "verified":
        text += f" · {result.algorithm} verified ✓"
    return Outcome(True, text, {"path": result.path})


def run_checksum(path: str, _settings, progress, cancel) -> Outcome:
    return Outcome(True, "Done", {"digests": ops.hash_path(path, None, progress, cancel)})


# ----------------------------------------------------------------------------
# Thread
# ----------------------------------------------------------------------------
class JobRunner(QThread):
    item_started = Signal(int)                       # index in this run
    progress = Signal(int, int, float, int)          # index, count, fraction, total bytes
    item_done = Signal(int, object)                  # index, Outcome
    all_done = Signal(bool)                          # True = cancelled

    def __init__(self, func, paths: List[str], settings, parent=None):
        super().__init__(parent)
        self._func, self._paths, self._settings = func, list(paths), settings
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        count = len(self._paths)
        for index, path in enumerate(self._paths):
            if self._cancel.is_set():
                break
            self.item_started.emit(index)
            try:
                total = ops.path_size(path)
            except OSError:
                total = 0
            last = [0.0]

            def report(fraction: float, index=index, total=total) -> None:
                now = time.monotonic()
                if fraction >= 1.0 or now - last[0] > 0.04:          # at most ~25 updates/s
                    last[0] = now
                    self.progress.emit(index, count, fraction, total)

            try:
                outcome = self._func(path, self._settings, report, self._cancel)
            except ops.OperationCancelled:
                outcome = Outcome(False, "Cancelled")
            except Exception as exc:
                outcome = Outcome(False, str(exc) or exc.__class__.__name__)
            self.item_done.emit(index, outcome)
        self.all_done.emit(self._cancel.is_set())


# ----------------------------------------------------------------------------
# Controller (GUI side)
# ----------------------------------------------------------------------------
class JobController(QObject):
    """Connects a SourceList + StatusProgress + main Button to a JobRunner."""

    outcome = Signal(int, object)        # row, Outcome
    finished = Signal(bool)              # True = everything succeeded

    def __init__(self, sources, status, button, parent=None):
        super().__init__(parent)
        self.sources, self.status, self.button = sources, status, button
        self.running = False
        self._runner = None
        self._rows: List[int] = []
        self._form = None
        self._results: List[Outcome] = []

    def toggle(self, form) -> None:
        if self.running:
            self._runner.cancel()
            self.status.set_message("Cancelling...")
        else:
            self.start(form)

    def start(self, form) -> None:
        error = form.validate()
        if error:
            return self.status.set_message(error, "error")
        pending = self.sources.pending()
        if not pending:
            return self.status.set_message(
                "Add at least one file or folder." if not self.sources.paths()
                else "Everything is already done.", "error")

        self._form, self._rows, self._results = form, [r for r, _ in pending], []
        for row in self._rows:
            self.sources.set_status(row, "Waiting")
        self._runner = JobRunner(form.run, [p for _, p in pending], form.settings(), self)
        self._runner.item_started.connect(self._on_started)
        self._runner.progress.connect(self._on_progress)
        self._runner.item_done.connect(self._on_item)
        self._runner.all_done.connect(self._on_all_done)
        self.running = True
        self.button.setText("Cancel")
        self.status.reset("Working...")
        self._runner.start()

    def shutdown(self) -> None:
        if self._runner and self.running:
            self._runner.cancel()
            self._runner.wait(5000)

    # -- signals from the thread ----------------------------------------------
    def _on_started(self, index: int) -> None:
        self.sources.set_status(self._rows[index], "Working...")

    def _on_progress(self, index: int, count: int, fraction: float, total: int) -> None:
        self.status.set_fraction((index + fraction) / count)
        text = self._form.VERB
        if total:
            text += f" {format_size(fraction * total)} / {format_size(total)}"
        if count > 1:
            text += f" · {index + 1}/{count}"
        self.status.set_message(text)

    def _on_item(self, index: int, outcome: Outcome) -> None:
        self.sources.set_status(self._rows[index], outcome.text, "ok" if outcome.ok else "error")
        self._results.append(outcome)
        self.outcome.emit(self._rows[index], outcome)

    def _on_all_done(self, cancelled: bool) -> None:
        self.running = False
        self.button.setText(self._form.ACTION)
        failed = [o for o in self._results if not o.ok]
        if cancelled:
            self.status.set_message("Cancelled", "error")
        elif failed:
            self.status.set_message(
                failed[0].text if len(self._results) == 1
                else f"{len(self._results) - len(failed)} done, {len(failed)} failed", "error")
        else:
            self.status.set_fraction(1.0)
            if len(self._results) == 1:
                text = self._results[0].text
                self.status.set_message(text if "✓" in text else text + " ✓", "ok")
            else:
                self.status.set_message(f"Done · {len(self._results)} items ✓", "ok")
        self.finished.emit(not cancelled and not failed)
