"""
gui/widgets.py - small reusable flat widgets.

    Button          flat button, colour fades on hover; icon-only variant (+ - ...)
    PasswordField   line edit with an eye (show/hide) and optional "generate" icon
    PathField       line edit + "..." folder picker
    SourceList      list of files/folders (+ status per row), optional drag & drop
    StatusProgress  progress bar that also shows the message ("Encrypting 12 / 40 MB")
    TabBar          flat tabs with an accent underline
    HashField       one hash in a rounded box (click = copy, green when it matches)
    Dots            small "loading" animation
    BaseWindow      dark title bar, fade-in, Esc closes
"""

import os
import secrets
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import (QPoint, QPointF, QRectF, QSize, Qt, QTimer, QVariantAnimation,
                            Signal)
from PySide6.QtGui import QAction, QColor, QFontMetrics, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QSizePolicy, QTreeWidget, QTreeWidgetItem, QWidget,
                               QAbstractItemView)

from . import styles as ui


def separator() -> QFrame:
    """1px horizontal line."""
    line = QFrame()
    line.setObjectName("sep")
    return line


# ----------------------------------------------------------------------------
# Buttons
# ----------------------------------------------------------------------------
class Button(QPushButton):
    """Flat button. primary=True -> accent colour. text="" + icon -> small square button."""

    def __init__(self, text: str = "", *, primary: bool = False, icon: Optional[str] = None,
                 tooltip: str = "", parent=None):
        super().__init__(text, parent)
        self._primary = primary
        self._icon_name = icon
        self._rest = QColor(ui.ACCENT if primary else ui.FIELD)
        self._hover = QColor(ui.ACCENT_HOVER if primary else ui.HOVER)
        self._color = QColor(self._rest)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(120)
        self._anim.valueChanged.connect(self._on_anim)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.TabFocus)
        if tooltip:
            self.setToolTip(tooltip)
        if icon and not text:
            self.setFixedSize(30, 30)
        else:
            self.setFixedHeight(30)

    def set_icon_name(self, name: str) -> None:
        self._icon_name = name
        self.update()

    def _on_anim(self, value) -> None:
        self._color = value
        self.update()

    def _fade(self, target: QColor) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._color)
        self._anim.setEndValue(target)
        self._anim.start()

    def enterEvent(self, event) -> None:
        if self.isEnabled():
            self._fade(self._hover)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._fade(self._rest)
        super().leaveEvent(event)

    def sizeHint(self) -> QSize:
        if self._icon_name and not self.text():
            return QSize(30, 30)
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 32, 30)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        enabled = self.isEnabled()
        fill = QColor(self._color) if enabled else QColor(ui.FIELD)
        if self.isDown() and enabled:
            fill = fill.darker(118)
        border = QColor(ui.ACCENT) if (self._primary or self.hasFocus()) else QColor(ui.BORDER)
        painter.setPen(QPen(border, 1))
        painter.setBrush(fill)
        painter.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 3, 3)

        color = "#FFFFFF" if self._primary else ui.FG
        if not enabled:
            color = ui.FG_DIM
        if self._icon_name and not self.text():
            pixmap = ui.svg_pixmap(self._icon_name, color, 16, self.devicePixelRatioF())
            painter.drawPixmap(QPointF((self.width() - 16) / 2, (self.height() - 16) / 2), pixmap)
        else:
            painter.setPen(QColor(color))
            painter.drawText(self.rect(), Qt.AlignCenter, self.text())


# ----------------------------------------------------------------------------
# Inputs
# ----------------------------------------------------------------------------
class PasswordField(QLineEdit):
    """Password box with an eye icon inside. generate=True adds a dice icon too."""

    revealed_changed = Signal(bool)

    def __init__(self, generate: bool = False, eye: bool = True, parent=None):
        super().__init__(parent)
        self.setEchoMode(QLineEdit.Password)
        self._eye = QAction(self)
        self._eye.setCheckable(True)
        self._eye.setToolTip("Show / hide the password")
        self._eye.setIcon(ui.svg_icon("eye_off"))
        self._eye.toggled.connect(self._on_toggled)
        if generate:
            dice = QAction(self)
            dice.setIcon(ui.svg_icon("dice"))
            dice.setToolTip("Generate a strong password")
            dice.triggered.connect(self.generate)
            self.addAction(dice, QLineEdit.TrailingPosition)
        if eye:
            self.addAction(self._eye, QLineEdit.TrailingPosition)

    def revealed(self) -> bool:
        return self._eye.isChecked()

    def set_revealed(self, on: bool) -> None:
        self._eye.setChecked(on)

    def generate(self) -> None:
        self.setText(secrets.token_urlsafe(18))
        self.set_revealed(True)                      # let the user SEE and save it

    def _on_toggled(self, on: bool) -> None:
        self.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        self._eye.setIcon(ui.svg_icon("eye" if on else "eye_off", ui.ACCENT if on else ui.FG_DIM))
        self.revealed_changed.emit(on)


class PathField(QWidget):
    """Folder path + "..." button. Empty = 'same folder as the source'."""

    def __init__(self, placeholder: str = "Same folder as the source", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        button = Button("...", tooltip="Choose a folder")
        button.setFixedWidth(38)
        button.clicked.connect(self._browse)
        layout.addWidget(self.edit, 1)
        layout.addWidget(button)

    def text(self) -> str:
        return self.edit.text().strip()

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder", self.text())
        if folder:
            self.edit.setText(os.path.normpath(folder))


# ----------------------------------------------------------------------------
# Source list
# ----------------------------------------------------------------------------
ROW_H = 26
_KIND_COLOR = {"ok": ui.OK, "error": ui.ERROR, "": ui.FG_DIM}


class SourceList(QTreeWidget):
    """Files/folders to process. full=drag & drop + header, compact=read-only mini list."""

    paths_dropped = Signal(list)

    def __init__(self, *, compact: bool = False, accept_drops: bool = False, parent=None):
        super().__init__(parent)
        self._compact = compact
        self._placeholder = "Drag & drop files or folders here" if accept_drops else ""
        self.setColumnCount(2)
        self.setHeaderLabels(["Path", "Status"])
        self.setRootIsDecorated(False)
        self.setIndentation(0)
        self.setUniformRowHeights(True)
        self.setTextElideMode(Qt.ElideMiddle)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSelectionMode(QAbstractItemView.NoSelection if compact
                              else QAbstractItemView.ExtendedSelection)
        header = self.header()
        header.setStretchLastSection(False)
        header.setSectionsMovable(False)
        header.setSectionResizeMode(0, header.ResizeMode.Stretch)
        header.setSectionResizeMode(1, header.ResizeMode.Fixed)
        self.setColumnWidth(1, 130 if compact else 190)
        if compact:
            self.setHeaderHidden(True)
        if accept_drops:
            self.setAcceptDrops(True)
            self.setDragDropMode(QAbstractItemView.DropOnly)

    # -- contents ----------------------------------------------------------
    def add_paths(self, paths) -> int:
        known = set(self.paths())
        added = 0
        for path in paths:
            path = os.path.normpath(str(path))
            if os.path.exists(path) and path not in known:
                item = QTreeWidgetItem([path, ""])
                item.setToolTip(0, path)
                item.setData(1, Qt.UserRole, "")
                self.addTopLevelItem(item)
                known.add(path)
                added += 1
        self.fit_rows()
        return added

    def paths(self) -> List[str]:
        return [self.topLevelItem(i).text(0) for i in range(self.topLevelItemCount())]

    def pending(self) -> List[tuple]:
        """(row, path) of the rows that are not finished successfully yet."""
        return [(i, self.topLevelItem(i).text(0)) for i in range(self.topLevelItemCount())
                if self.topLevelItem(i).data(1, Qt.UserRole) != "ok"]

    def remove_selected(self) -> None:
        for item in self.selectedItems():
            self.takeTopLevelItem(self.indexOfTopLevelItem(item))
        self.fit_rows()

    def set_status(self, row: int, text: str, kind: str = "") -> None:
        item = self.topLevelItem(row)
        if item is None:
            return
        item.setText(1, text)
        item.setToolTip(1, text)
        item.setData(1, Qt.UserRole, kind)
        item.setForeground(1, QColor(_KIND_COLOR.get(kind, ui.FG_DIM)))

    def clear_status(self) -> None:
        for i in range(self.topLevelItemCount()):
            self.set_status(i, "")

    def fit_rows(self, min_rows: int = 1, max_rows: int = 4) -> None:
        """Compact lists grow with the number of items (up to max_rows)."""
        if not self._compact:
            return
        count = self.topLevelItemCount()
        rows = max(min_rows, min(count, max_rows))
        self.setFixedHeight(rows * ROW_H + 4)
        self.setColumnHidden(1, count <= 1)          # one item: the status bar says it all

    # -- drag & drop / placeholder ----------------------------------------------
    def _urls(self, event) -> List[str]:
        return [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]

    def dragEnterEvent(self, event) -> None:
        if self._urls(event):
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        self.paths_dropped.emit(self._urls(event))
        event.acceptProposedAction()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._placeholder and self.topLevelItemCount() == 0:
            painter = QPainter(self.viewport())
            painter.setPen(QColor(ui.FG_DIM))
            painter.drawText(self.viewport().rect(), Qt.AlignCenter, self._placeholder)


# ----------------------------------------------------------------------------
# Progress + status text
# ----------------------------------------------------------------------------
class StatusProgress(QWidget):
    """Progress bar with the message written on it. The fill eases to its target."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._shown = 0.0
        self._text = "Ready"
        self._kind = ""
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(180)
        self._anim.valueChanged.connect(self._on_anim)
        self.setFixedHeight(30)
        self.setMinimumWidth(140)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def _on_anim(self, value) -> None:
        self._shown = float(value)
        self.update()

    def set_fraction(self, fraction: float) -> None:
        fraction = max(0.0, min(1.0, fraction))
        self._anim.stop()
        self._anim.setStartValue(self._shown)
        self._anim.setEndValue(fraction)
        self._anim.start()

    def set_message(self, text: str, kind: str = "") -> None:
        self._text, self._kind = text, kind
        self.setToolTip(text)
        self.update()

    def reset(self, text: str = "Ready") -> None:
        self._anim.stop()
        self._shown = 0.0
        self.set_message(text)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        box = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setPen(QPen(QColor(ui.BORDER), 1))
        painter.setBrush(QColor(ui.FIELD))
        painter.drawRoundedRect(box, 3, 3)

        fill_w = box.width() * self._shown
        text = QFontMetrics(self.font()).elidedText(self._text, Qt.ElideRight,
                                                    int(box.width()) - 16)
        painter.save()
        painter.setClipRect(QRectF(box.left(), box.top(), fill_w, box.height()))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(ui.ACCENT))
        painter.drawRoundedRect(box, 3, 3)
        painter.setPen(QColor("#FFFFFF"))
        painter.drawText(box, Qt.AlignCenter, text)
        painter.restore()

        painter.save()
        painter.setClipRect(QRectF(box.left() + fill_w, box.top(), box.width(), box.height()))
        painter.setPen(QColor({"ok": ui.OK, "error": ui.ERROR}.get(self._kind, ui.FG)))
        painter.drawText(box, Qt.AlignCenter, text)
        painter.restore()


# ----------------------------------------------------------------------------
# Tabs
# ----------------------------------------------------------------------------
class _Tab(QPushButton):
    def __init__(self, title: str, parent=None):
        super().__init__(title, parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)
        self._hover = False
        self.setFixedHeight(38)

    def sizeHint(self) -> QSize:
        return QSize(self.fontMetrics().horizontalAdvance(self.text()) + 40, 38)

    def enterEvent(self, event) -> None:
        self._hover = True
        self.update()

    def leaveEvent(self, event) -> None:
        self._hover = False
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        font = self.font()
        font.setBold(True)
        painter.setFont(font)
        active = self.isChecked()
        painter.setPen(QColor(ui.FG if (active or self._hover) else ui.FG_DIM))
        painter.drawText(self.rect().adjusted(0, 0, 0, -2), Qt.AlignCenter, self.text())
        if active:
            painter.fillRect(QRectF(0, self.height() - 2, self.width(), 2), QColor(ui.ACCENT))


class TabBar(QWidget):
    changed = Signal(int)

    def __init__(self, titles: List[str], parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._tabs = []
        for index, title in enumerate(titles):
            tab = _Tab(title)
            tab.clicked.connect(lambda _=False, i=index: self.select(i))
            layout.addWidget(tab)
            self._tabs.append(tab)
        layout.addStretch(1)
        self.select(0, notify=False)

    def select(self, index: int, notify: bool = True) -> None:
        for i, tab in enumerate(self._tabs):
            tab.setChecked(i == index)
        if notify:
            self.changed.emit(index)


# ----------------------------------------------------------------------------
# Hashes
# ----------------------------------------------------------------------------
class HashField(QLabel):
    """A hash in a rounded box. Click = copy. matched=True -> green border."""

    copied = Signal(str)

    def __init__(self, value: str = "", placeholder: str = "", parent=None):
        super().__init__(parent)
        self._value = value
        self._placeholder = placeholder
        self._matched = False
        self._flash = False
        self.setFixedHeight(32)
        self.setMinimumWidth(80)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._refresh()

    def value(self) -> str:
        return self._value

    def set_value(self, value: str) -> None:
        self._value = value
        self._refresh()

    def set_matched(self, matched: bool) -> None:
        self._matched = matched
        self.update()

    def _refresh(self) -> None:
        self.setCursor(Qt.PointingHandCursor if self._value else Qt.ArrowCursor)
        self.setToolTip(self._value and f"{self._value}\n(click to copy)")
        self.update()

    def mousePressEvent(self, event) -> None:
        if self._value and event.button() == Qt.LeftButton:
            QGuiApplication.clipboard().setText(self._value)
            self._flash = True
            self.update()
            QTimer.singleShot(700, self._end_flash)
            self.copied.emit(self._value)

    def _end_flash(self) -> None:
        self._flash = False
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        box = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        painter.setPen(QPen(QColor(ui.OK if self._matched else ui.BORDER),
                            2 if self._matched else 1))
        painter.setBrush(QColor(ui.FIELD))
        painter.drawRoundedRect(box, 4, 4)

        if self._flash:
            text, color = "Copied ✓", ui.OK
        elif self._value:
            text, color = self._value, ui.FG
        else:
            text, color = self._placeholder, ui.FG_DIM
        text = QFontMetrics(self.font()).elidedText(text, Qt.ElideRight, int(box.width()) - 20)
        painter.setPen(QColor(color))
        painter.drawText(box.adjusted(10, 0, -10, 0), Qt.AlignVCenter | Qt.AlignLeft, text)


class Dots(QWidget):
    """Five dots that light up one after the other ("working...")."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phase = 0
        self._timer = QTimer(self)
        self._timer.setInterval(130)
        self._timer.timeout.connect(self._tick)
        self.setFixedSize(60, 14)

    def start(self) -> None:
        self._timer.start()
        self.show()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _tick(self) -> None:
        self._phase = (self._phase + 1) % 5
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        for i in range(5):
            color = QColor(ui.FG if i == self._phase else ui.BORDER)
            painter.setBrush(color)
            painter.drawEllipse(QPointF(6 + i * 12, 7), 2.5, 2.5)


# ----------------------------------------------------------------------------
# Window base
# ----------------------------------------------------------------------------
class BaseWindow(QWidget):
    """Common behaviour: dark title bar, soft fade-in, Esc closes."""

    def __init__(self, title: str, flags=Qt.Window):
        super().__init__(None, flags)
        self.setObjectName("root")
        self.setWindowTitle(title)
        self.setWindowOpacity(0.0)
        self._shown_once = False
        self._fade = None

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._shown_once:
            self._shown_once = True
            ui.dark_titlebar(self)
            self._fade = ui.fade_in(self)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)
