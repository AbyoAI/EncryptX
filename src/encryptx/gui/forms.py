"""
gui/forms.py - the option panels (Encrypt / Decrypt).

The SAME form class is used by the big window (wide=True, two columns) and by the
right-click dialogs (wide=False, one tall column).

Each form offers:  ACTION / VERB (button + progress text), run (worker function),
validate() -> error text or None, settings() -> plain dataclass.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QGridLayout, QHBoxLayout, QLabel,
                               QVBoxLayout, QWidget)

from ..core.file_operations import CHECKSUM_ALGOS
from ..crypto.modern import ALGORITHMS, DEFAULT_ALGORITHM, KDFS
from . import jobs
from .widgets import HashField, PasswordField, PathField

CHECKSUM_OFF = "Off"


def _label(text: str) -> QLabel:
    label = QLabel(text)
    label.setMinimumWidth(78)
    return label


def _grid() -> QGridLayout:
    grid = QGridLayout()
    grid.setContentsMargins(0, 0, 0, 0)
    grid.setHorizontalSpacing(10)
    grid.setVerticalSpacing(9)
    return grid


class EncryptForm(QWidget):
    ACTION = "Encrypt"
    VERB = "Encrypting"
    run = staticmethod(jobs.run_encrypt)

    def __init__(self, wide: bool = False, parent=None):
        super().__init__(parent)
        self.out = PathField()
        self.algo = QComboBox()
        self.algo.addItems(list(ALGORITHMS))
        self.algo.setCurrentText(DEFAULT_ALGORITHM)
        self.kdf = QComboBox()
        self.kdf.addItems(KDFS)
        self.pw = PasswordField(generate=True)
        self.pw2 = PasswordField(eye=False)                  # only the main field has the eye
        self.pw2.setPlaceholderText("Repeat the password")
        self.pw.setPlaceholderText("Password")
        self.checksum = QComboBox()
        self.checksum.addItems([CHECKSUM_OFF] + list(CHECKSUM_ALGOS))
        self.checksum.setCurrentText("SHA-256")
        self.digest = HashField(placeholder="Shown after encryption")   # tall layout only
        self.compress = QCheckBox("Compress")
        self.hide_name = QCheckBox("Hide file names")
        self.delete = QCheckBox("Delete originals")
        self.compress.setChecked(True)
        self.hide_name.setChecked(True)

        self._repeat_label = _label("Repeat")
        self.pw.revealed_changed.connect(self._sync_repeat)
        self._wide = wide
        self._build_wide() if wide else self._build_tall()
        self._sync_repeat(False)

    # -- layouts ------------------------------------------------------------
    def _build_wide(self) -> None:
        g = _grid()
        g.setColumnStretch(1, 1)
        g.setColumnStretch(3, 1)
        g.addWidget(_label("Output"), 0, 0)
        g.addWidget(self.out, 0, 1, 1, 3)
        g.addWidget(_label("Algorithm"), 1, 0)
        g.addWidget(self.algo, 1, 1)
        g.addWidget(_label("Key derivation"), 1, 2)
        g.addWidget(self.kdf, 1, 3)
        g.addWidget(_label("Password"), 2, 0)
        g.addWidget(self.pw, 2, 1)
        g.addWidget(_label("Checksum"), 2, 2)
        g.addWidget(self.checksum, 2, 3)
        g.addWidget(self._repeat_label, 3, 0)
        g.addWidget(self.pw2, 3, 1)
        row = QHBoxLayout()
        row.setSpacing(20)
        for check in (self.compress, self.hide_name, self.delete):
            row.addWidget(check)
        row.addStretch(1)
        g.addLayout(row, 4, 0, 1, 4)
        self.setLayout(g)

    def _build_tall(self) -> None:
        g = _grid()
        g.setColumnStretch(1, 1)
        g.addWidget(_label("Output"), 0, 0)
        g.addWidget(self.out, 0, 1)
        g.addWidget(_label("Algorithm"), 1, 0)
        g.addWidget(self.algo, 1, 1)
        g.addWidget(_label("Key derivation"), 2, 0)
        g.addWidget(self.kdf, 2, 1)
        g.addWidget(_label("Password"), 3, 0)
        g.addWidget(self.pw, 3, 1)
        g.addWidget(self._repeat_label, 4, 0)
        g.addWidget(self.pw2, 4, 1)
        g.addWidget(_label("Checksum"), 5, 0)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.checksum.setFixedWidth(112)
        row.addWidget(self.checksum)
        row.addWidget(self.digest, 1)
        g.addLayout(row, 5, 1)
        checks = QVBoxLayout()
        checks.setSpacing(6)
        for check in (self.compress, self.hide_name, self.delete):
            checks.addWidget(check)
        g.addLayout(checks, 6, 1)
        self.setLayout(g)

    def _sync_repeat(self, revealed: bool) -> None:
        """The repeat box is only needed while the password is hidden."""
        self.pw2.setVisible(not revealed)
        self._repeat_label.setVisible(not revealed)

    # -- API ----------------------------------------------------------------
    def set_digest(self, algorithm: str, digest: str) -> None:
        self.digest.set_value(digest)

    def validate(self):
        if not self.pw.text():
            return "Enter a password."
        if not self.pw.revealed() and self.pw.text() != self.pw2.text():
            return "The passwords do not match."
        return None

    def settings(self) -> jobs.EncryptSettings:
        checksum = self.checksum.currentText()
        return jobs.EncryptSettings(
            self.out.text(), self.pw.text(), self.algo.currentText(), self.kdf.currentText(),
            "" if checksum == CHECKSUM_OFF else checksum, self.compress.isChecked(),
            self.hide_name.isChecked(), self.delete.isChecked())


class DecryptForm(QWidget):
    ACTION = "Decrypt"
    VERB = "Decrypting"
    run = staticmethod(jobs.run_decrypt)

    def __init__(self, wide: bool = False, parent=None):
        super().__init__(parent)
        self.out = PathField()
        self.pw = PasswordField()
        self.pw.setPlaceholderText("Password")
        self.delete = QCheckBox("Delete encrypted files afterwards")

        g = _grid()
        g.setColumnStretch(1, 1)
        g.addWidget(_label("Output"), 0, 0)
        g.addWidget(self.out, 0, 1)
        g.addWidget(_label("Password"), 1, 0)
        g.addWidget(self.pw, 1, 1)
        g.addWidget(self.delete, 2, 1)
        self.setLayout(g)

    def validate(self):
        return None if self.pw.text() else "Enter the password."

    def settings(self) -> jobs.DecryptSettings:
        return jobs.DecryptSettings(self.out.text(), self.pw.text(), self.delete.isChecked())
