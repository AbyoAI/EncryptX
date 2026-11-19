"""GUI tests: run headless (QT_QPA_PLATFORM=offscreen, see conftest.py)."""
import os
import time

import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from encryptx.gui import styles
from encryptx.gui.dialogs import ActionDialog, ChecksumDialog
from encryptx.gui.main_window import MAX_SIZE, MIN_SIZE, MainWindow
from encryptx.platform.single_instance import SingleInstance


@pytest.fixture(scope="session")
def app():
    application = QApplication.instance() or QApplication([])
    styles.apply_theme(application)
    return application


def wait_until(app, condition, timeout=30):
    end = time.time() + timeout
    while time.time() < end and not condition():
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    return condition()


def dispose(app, window):
    window.close()
    window.deleteLater()
    app.processEvents()


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "secret.bat"
    path.write_bytes(b"@echo off\n" * 20000)
    return str(path)


def test_main_window_limits_and_tabs(app, sample):
    w = MainWindow([sample, sample])                     # duplicate is ignored
    w.show()
    assert w.sources.paths() == [os.path.normpath(sample)]
    assert (w.minimumWidth(), w.minimumHeight()) == MIN_SIZE
    assert (w.maximumWidth(), w.maximumHeight()) == MAX_SIZE
    w.tabs.select(1)
    assert w.stack.currentIndex() == 1 and w.main_button.text() == "Decrypt"
    dispose(app, w)


def test_repeat_password_only_while_hidden(app):
    w = ActionDialog("encrypt", [])
    w.show()
    form = w.form
    assert form.pw2.isVisible()
    form.pw.setText("abc")
    assert form.validate() == "The passwords do not match."
    form.pw.set_revealed(True)                           # eye open -> no repeat needed
    assert not form.pw2.isVisible() and form.validate() is None
    form.pw.set_revealed(False)
    form.pw2.setText("abc")
    assert form.validate() is None
    dispose(app, w)


def test_encrypt_then_decrypt_dialogs(app, sample, tmp_path):
    w = ActionDialog("encrypt", [sample])
    w.show()
    w.form.pw.setText("pw1")
    w.form.pw2.setText("pw1")
    w.main_button.click()
    assert wait_until(app, lambda: not w.controller.running)
    assert w.folder_button.isVisible()
    assert len(w.form.digest.value()) == 64              # SHA-256 shown in the checksum box
    encrypted = w._last_output
    assert encrypted.endswith(".encx")
    dispose(app, w)

    d = ActionDialog("decrypt", [encrypted])
    d.show()
    d.form.pw.setText("WRONG")
    d.main_button.click()
    assert wait_until(app, lambda: not d.controller.running)
    assert d.sources.pending()                           # failed -> can be retried
    d.form.pw.setText("pw1")
    d.form.out.edit.setText(str(tmp_path / "restored"))
    d.main_button.click()
    assert wait_until(app, lambda: not d.controller.running)
    assert not d.sources.pending()
    assert "verified" in d.sources.topLevelItem(0).text(1) or "verified" in d.status._text
    assert (tmp_path / "restored" / "secret.bat").read_bytes() == b"@echo off\n" * 20000
    dispose(app, d)


def test_checksum_dialog_match_and_no_match(app, sample):
    w = ChecksumDialog([sample])
    w.show()
    section = w._sections[os.path.normpath(sample)]
    assert wait_until(app, lambda: bool(section.digests) and w._runner is None)
    w.compare.setText(section.digests["SHA-256"].upper())
    assert "Match" in w.verdict.text() and "SHA-256" in w.verdict.text()
    assert section.fields["SHA-256"]._matched and not section.fields["MD5"]._matched
    w.compare.setText("deadbeef")
    assert w.verdict.text().endswith("No match")
    w.compare.setText("")
    assert w.verdict.text() == ""
    dispose(app, w)


def test_single_instance_forwards_paths(app):
    first, second = SingleInstance("EncryptX-test"), SingleInstance("EncryptX-test")
    received = []
    assert first.claim([])
    first.paths_received.connect(received.extend)
    assert second.claim(["/a/file.txt"]) is False        # handed over to the first one
    assert wait_until(app, lambda: received == ["/a/file.txt"], timeout=5)
