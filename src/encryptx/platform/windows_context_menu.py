"""
platform/windows_context_menu.py - Explorer right-click menu (per user, no admin).

    EncryptX  >  Encrypt     (files + folders)
              >  Decrypt     (.encx files only)
              >  Checksum    (files + folders)
    + the .encx file icon and "double-click = Decrypt"

The Inno Setup installer (installer/EncryptX.iss) writes the SAME keys, so end
users never need this module. It is for development:

    python -m encryptx install-menu      /     python -m encryptx uninstall-menu
"""

import os
import sys
from pathlib import Path

EXTENSION = ".encx"
FILE_GROUP = r"Software\Classes\*\shell\EncryptX"            # right-click on a file
FOLDER_GROUP = r"Software\Classes\Directory\shell\EncryptX"  # right-click on a folder

# (mode, menu text, optional Explorer filter). Key names 01_, 02_ ... keep the order.
_ENCX_ONLY = f'System.FileExtension:="{EXTENSION}"'
GROUPS = {
    FILE_GROUP: [("encrypt", "Encrypt", None),
                 ("decrypt", "Decrypt", _ENCX_ONLY),
                 ("checksum", "Checksum", None)],
    FOLDER_GROUP: [("encrypt", "Encrypt", None),
                   ("checksum", "Checksum", None)],
}


def command_line(mode: str) -> str:
    """The command Windows runs when a menu item is clicked."""
    if getattr(sys, "frozen", False):                       # installed EncryptX.exe
        return f'"{sys.executable}" {mode} "%1"'
    pyw = Path(sys.executable).with_name("pythonw.exe")     # no console window
    python = pyw if pyw.exists() else Path(sys.executable)
    launcher = Path(__file__).resolve().parents[3] / "run.py"   # <repo>/run.py
    return f'"{python}" "{launcher}" {mode} "%1"'


def _assets() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "assets"
    return Path(__file__).resolve().parents[3] / "assets"


def _icon() -> str:
    """Icon of the EncryptX menu group = the application icon."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}",0'
    return str(_assets() / "icon.ico")


FILE_TYPE = "EncryptX.File"
FILE_TYPE_KEY = rf"Software\Classes\{FILE_TYPE}"
EXTENSION_KEY = rf"Software\Classes\{EXTENSION}"


def _set(path: str, name: str, value: str) -> None:
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def _delete_tree(path: str) -> None:
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        return
    with key:
        while True:
            try:
                child = winreg.EnumKey(key, 0)
            except OSError:
                break
            _delete_tree(path + "\\" + child)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)


def _refresh_explorer() -> None:
    try:
        import ctypes
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)   # SHCNE_ASSOCCHANGED
    except Exception:
        pass


def install() -> None:
    if os.name != "nt":
        raise RuntimeError("The context menu is Windows only.")
    uninstall(refresh=False)
    for group, items in GROUPS.items():
        _set(group, "MUIVerb", "EncryptX")          # text of the group
        _set(group, "SubCommands", "")              # empty value = "this verb is a submenu"
        _set(group, "Icon", _icon())
        for number, (mode, label, applies_to) in enumerate(items, 1):
            item = f"{group}\\shell\\{number:02d}_{mode}"
            _set(item, "MUIVerb", label)
            if applies_to:
                _set(item, "AppliesTo", applies_to)
            _set(item + r"\command", "", command_line(mode))

    # .encx files: the "file" icon + double-click = Decrypt
    _set(EXTENSION_KEY, "", FILE_TYPE)
    _set(FILE_TYPE_KEY, "", "EncryptX encrypted file")
    _set(FILE_TYPE_KEY + r"\DefaultIcon", "", str(_assets() / "file_icon.ico"))
    _set(FILE_TYPE_KEY + r"\shell\open\command", "", command_line("decrypt"))
    _refresh_explorer()


def uninstall(refresh: bool = True) -> None:
    if os.name != "nt":
        return
    for group in (*GROUPS, EXTENSION_KEY, FILE_TYPE_KEY):
        _delete_tree(group)
    if refresh:
        _refresh_explorer()
