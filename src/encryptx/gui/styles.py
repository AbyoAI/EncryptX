"""
gui/styles.py - classic dark FLAT theme for Qt (QSS) + small drawing helpers.

* Colours live here only.
* Icons are tiny inline SVGs drawn in the colour you ask for (sharp on any DPI).
"""

import ctypes
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from string import Template

from PySide6.QtCore import QByteArray, QPropertyAnimation, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication, QWidget

# ---- palette ---------------------------------------------------------------
BG = "#1E1E1E"
SURFACE = "#252526"
FIELD = "#2D2D30"
BORDER = "#3E3E42"
HOVER = "#3A3A40"
FG = "#D4D4D4"
FG_DIM = "#8B8B8B"
ACCENT = "#3794FF"
ACCENT_HOVER = "#5AA9FF"
SELECT = "#264F78"
OK = "#4EC9B0"
ERROR = "#F48771"
FONT_FAMILY = "Segoe UI"
FONT_SIZE = 9


def asset(name: str) -> Path:
    """assets/<name> - works from source and inside the PyInstaller bundle."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[3]))
    return base / "assets" / name


# ---- icons -----------------------------------------------------------------
_ICONS = {
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "minus": '<path d="M5 12h14"/>',
    "eye": '<path d="M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z"/>'
           '<circle cx="12" cy="12" r="3"/>',
    "eye_off": '<path d="M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z"/>'
               '<circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
    "dice": '<rect x="4" y="4" width="16" height="16" rx="3"/>'
            '<g fill="currentColor" stroke="none"><circle cx="9" cy="9" r="1.3"/>'
            '<circle cx="15" cy="9" r="1.3"/><circle cx="9" cy="15" r="1.3"/>'
            '<circle cx="15" cy="15" r="1.3"/></g>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
}


def _svg(name: str, color: str) -> bytes:
    body = _ICONS[name].replace("currentColor", color)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="2" stroke-linecap="round" '
            f'stroke-linejoin="round">{body}</svg>').encode()


@lru_cache(maxsize=None)
def svg_pixmap(name: str, color: str, size: int = 16, dpr: float = 2.0) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(_svg(name, color)))
    pixmap = QPixmap(int(size * dpr), int(size * dpr))
    pixmap.fill(Qt.transparent)
    pixmap.setDevicePixelRatio(dpr)
    painter = QPainter(pixmap)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return pixmap


def svg_icon(name: str, color: str = FG_DIM, size: int = 16) -> QIcon:
    return QIcon(svg_pixmap(name, color, size))


# ---- stylesheet ------------------------------------------------------------
_QSS = Template("""
QWidget { color: $FG; font-family: "$FONT"; font-size: ${SIZE}pt; }
QWidget#root { background: $BG; }
QLabel { background: transparent; }
QLabel#dim { color: $FG_DIM; }
QLabel#title { font-weight: 600; }
QFrame#sep { background: $BORDER; border: none; min-height: 1px; max-height: 1px; }

QLineEdit { background: $FIELD; border: 1px solid $BORDER; border-radius: 3px;
            padding: 5px 7px; min-height: 18px; selection-background-color: $SELECT; }
QLineEdit:hover { border-color: #55555B; }
QLineEdit:focus { border-color: $ACCENT; }
QLineEdit:read-only { color: $FG_DIM; }
QLineEdit QToolButton { background: transparent; border: none; border-radius: 3px; padding: 2px; }
QLineEdit QToolButton:hover { background: $HOVER; }

QComboBox { background: $FIELD; border: 1px solid $BORDER; border-radius: 3px;
            padding: 5px 8px; min-height: 18px; }
QComboBox:hover { border-color: #55555B; }
QComboBox:focus, QComboBox:on { border-color: $ACCENT; }
QComboBox::drop-down { border: none; width: 24px; subcontrol-origin: padding;
                       subcontrol-position: center right; }
QComboBox::down-arrow { image: url($CHEVRON); width: 10px; height: 6px; }
QComboBox QAbstractItemView { background: $FIELD; border: 1px solid $BORDER; outline: 0;
                              selection-background-color: $SELECT; padding: 2px; }

QCheckBox { spacing: 7px; background: transparent; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #5A5A60;
                       border-radius: 2px; background: $FIELD; }
QCheckBox::indicator:hover { border-color: $ACCENT; }
QCheckBox::indicator:checked { background: $ACCENT; border-color: $ACCENT; image: url($CHECK); }

QTreeWidget { background: $FIELD; border: 1px solid $BORDER; border-radius: 3px; outline: 0; }
QTreeWidget::item { height: 26px; padding-left: 4px; border: none; }
QTreeWidget::item:selected { background: $SELECT; color: #FFFFFF; }
QHeaderView::section { background: $SURFACE; color: $FG_DIM; border: none; padding: 4px 8px; }

QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: $BORDER; min-height: 28px; border-radius: 3px; margin: 2px; }
QScrollBar::handle:vertical:hover { background: #55555B; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: $BORDER; min-width: 28px; border-radius: 3px; margin: 2px; }
QScrollBar::handle:horizontal:hover { background: #55555B; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

QMenu { background: $FIELD; border: 1px solid $BORDER; padding: 4px; }
QMenu::item { padding: 6px 24px 6px 12px; border-radius: 2px; }
QMenu::item:selected { background: $SELECT; }
QToolTip { background: $SURFACE; color: $FG; border: 1px solid $BORDER; padding: 4px 6px; }
""")


def _write_qss_images() -> dict:
    """QSS can only use images from files -> write the two tiny SVGs to a temp folder."""
    folder = Path(tempfile.gettempdir()) / "encryptx_ui"
    folder.mkdir(exist_ok=True)
    (folder / "chevron.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="6" viewBox="0 0 10 6">'
        f'<path d="M1 1l4 4 4-4" fill="none" stroke="{FG_DIM}" stroke-width="1.6" '
        'stroke-linecap="round" stroke-linejoin="round"/></svg>')
    (folder / "check.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 12 12">'
        '<path d="M2.5 6.3l2.4 2.4 4.6-5" fill="none" stroke="#FFFFFF" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round"/></svg>')
    return {"CHEVRON": (folder / "chevron.svg").as_posix(),
            "CHECK": (folder / "check.svg").as_posix()}


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setFont(QFont(FONT_FAMILY, FONT_SIZE))
    palette = QPalette()
    for role, color in ((QPalette.Window, BG), (QPalette.WindowText, FG), (QPalette.Base, FIELD),
                        (QPalette.AlternateBase, SURFACE), (QPalette.Text, FG),
                        (QPalette.Button, FIELD), (QPalette.ButtonText, FG),
                        (QPalette.ToolTipBase, SURFACE), (QPalette.ToolTipText, FG),
                        (QPalette.Highlight, SELECT), (QPalette.HighlightedText, "#FFFFFF"),
                        (QPalette.PlaceholderText, FG_DIM)):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet(_QSS.substitute(
        FG=FG, FG_DIM=FG_DIM, BG=BG, SURFACE=SURFACE, FIELD=FIELD, BORDER=BORDER, HOVER=HOVER,
        ACCENT=ACCENT, SELECT=SELECT, FONT=FONT_FAMILY, SIZE=FONT_SIZE, **_write_qss_images()))


# ---- window helpers --------------------------------------------------------
def dark_titlebar(widget: QWidget) -> None:
    """Dark title bar on Windows 10/11 (ignored elsewhere)."""
    try:
        hwnd = int(widget.winId())
        value = ctypes.c_int(1)
        for attribute in (20, 19):                      # 20 = Win11 / Win10 2004+, 19 = older
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def fade_in(widget: QWidget, duration: int = 160) -> QPropertyAnimation:
    animation = QPropertyAnimation(widget, b"windowOpacity", widget)
    animation.setDuration(duration)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.start()
    return animation
