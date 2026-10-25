"""EncryptX: Windows tool for file/folder encryption."""

import base64
import json
import os
import queue
import secrets
import shutil
import struct
import sys
import tempfile
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM, AESGCM, AESOCB3, ChaCha20Poly1305)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
APP_NAME = "EncryptX"
EXTENSION = ".encx"

# Layout of a modern .encx file:
#   salt (16) | header nonce (12) | encrypted header (HEADER_SIZE + 16 tag) | encrypted data
HEADER_SIZE = 1024          # fixed size => the length of the file name is not leaked
SALT_LEN, HNONCE_LEN, TAG_LEN = 16, 12, 16
PREFIX_LEN = SALT_LEN + HNONCE_LEN + HEADER_SIZE + TAG_LEN
AUTO = "Modern (auto-detect)"   # algorithm is read from the encrypted header

# Colors (dark theme, taken from your reference UI)
BG = "#1E1E1E"        # window background
PANEL = "#2B2B2B"     # inputs / panels
BORDER = "#3C3C3C"
FG = "#E1E1E1"        # text
FG_DIM = "#9A9A9A"
ACCENT = "#4A90D9"    # blue accent
ACCENT_HOVER = "#5BA0E8"
ERROR = "#E06C6C"
OK = "#6CC070"


# ----------------------------------------------------------------------------
# ENCRYPTION ALGORITHMS
# Every class below has the same two methods:
#       encrypt(nonce, data, aad)  /  decrypt(nonce, data, aad)
# so the rest of the program does not care which one is used.
# ----------------------------------------------------------------------------
class EncryptThenMac:
    """Plain cipher + HMAC-SHA256 (encrypt-then-MAC). Needs a 64-byte key:
    first 32 bytes encrypt, last 32 bytes authenticate."""

    algorithm = algorithms.AES      # block cipher
    mode = modes.CBC                # CBC or CTR
    needs_padding = True            # CBC needs padding, CTR does not

    def __init__(self, key: bytes):
        self.enc_key, self.mac_key = key[:32], key[32:]

    def _mac(self, nonce, aad, ciphertext):
        h = crypto_hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(aad + nonce + ciphertext)
        return h

    def encrypt(self, nonce, data, aad):
        if self.needs_padding:
            padder = padding.PKCS7(128).padder()
            data = padder.update(data) + padder.finalize()
        encryptor = Cipher(self.algorithm(self.enc_key), self.mode(nonce)).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + self._mac(nonce, aad, ciphertext).finalize()

    def decrypt(self, nonce, blob, aad):
        ciphertext, tag = blob[:-32], blob[-32:]
        self._mac(nonce, aad, ciphertext).verify(tag)       # raises InvalidSignature
        decryptor = Cipher(self.algorithm(self.enc_key), self.mode(nonce)).decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()
        if self.needs_padding:
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(data) + unpadder.finalize()
        return data


class AesCbcHmac(EncryptThenMac):
    pass


class AesCtrHmac(EncryptThenMac):
    mode = modes.CTR
    needs_padding = False


class CamelliaCbcHmac(EncryptThenMac):
    algorithm = algorithms.Camellia


# name -> (class, key length in bytes, nonce length in bytes)
ALGORITHMS = {
    "AES-256-GCM": (AESGCM, 32, 12),
    "AES-192-GCM": (AESGCM, 24, 12),
    "AES-128-GCM": (AESGCM, 16, 12),
    "ChaCha20-Poly1305": (ChaCha20Poly1305, 32, 12),
    "AES-256-CCM": (AESCCM, 32, 12),
    "AES-256-OCB3": (AESOCB3, 32, 12),
    "AES-256-CBC + HMAC-SHA256": (AesCbcHmac, 64, 16),
    "AES-256-CTR + HMAC-SHA256": (AesCtrHmac, 64, 16),
    "Camellia-256-CBC + HMAC-SHA256": (CamelliaCbcHmac, 64, 16),
}
KDFS = ["Scrypt", "PBKDF2-SHA256"]



def derive_key(password: str, salt: bytes, kdf: str, key_len: int) -> bytes:
    """Turn the user's text key into a strong binary key."""
    data = password.encode("utf-8")
    if kdf == "Scrypt":
        return Scrypt(salt=salt, length=key_len, n=2**15, r=8, p=1).derive(data)
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=600_000
    ).derive(data)


# ----------------------------------------------------------------------------
# File container (header + data)
# ----------------------------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def header_key(master: bytes) -> bytes:
    """Key that protects the header (derived from the master key)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"EncryptX header").derive(master)


def body_key(master: bytes, length: int) -> bytes:
    """Key that protects the file data (derived from the master key)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=b"EncryptX body").derive(master)


def pack_header_block(header: dict) -> bytes:
    """JSON header -> fixed-size block (2-byte length + JSON + random padding)."""
    raw = json.dumps(header, ensure_ascii=False).encode("utf-8")
    if len(raw) > HEADER_SIZE - 2:
        raise ValueError("The file name is too long.")
    return (struct.pack(">H", len(raw)) + raw
            + secrets.token_bytes(HEADER_SIZE - 2 - len(raw)))


def unpack_header_block(block: bytes) -> dict:
    (length,) = struct.unpack(">H", block[:2])
    return json.loads(block[2:2 + length].decode("utf-8"))


def unique_path(path: Path) -> Path:
    """If the path exists, return 'name (1).ext', 'name (2).ext', ..."""
    if not path.exists():
        return path
    i = 1
    while True:
        candidate = path.with_name(f"{path.stem} ({i}){path.suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def delete_path(p: str):
    if os.path.isdir(p):
        shutil.rmtree(p, ignore_errors=True)
    elif os.path.exists(p):
        os.remove(p)


# ----------------------------------------------------------------------------
# Encrypt / Decrypt  (no GUI code here)
# ----------------------------------------------------------------------------
@dataclass
class EncryptOptions:
    algo: str                       # name from ALGORITHMS
    key: str                        # the text key typed by the user
    out_dir: str                    # where to write the .encx file
    kdf: str = "Scrypt"             # modern only
    compress: bool = True           # modern only
    hide_name: bool = True          # modern only: random output file name


def encrypt_path(src: str, opts: EncryptOptions) -> str:
    """Encrypt a file or folder. Returns the path of the .encx file."""
    src_path = Path(src)
    is_dir = src_path.is_dir()
    temp_zip = None

    try:
        # Folders are zipped first, then encrypted like a normal file.
        if is_dir:
            temp_zip = shutil.make_archive(
                os.path.join(tempfile.gettempdir(), "encx_" + secrets.token_hex(4)),
                "zip", root_dir=str(src_path))
            data = Path(temp_zip).read_bytes()
        else:
            data = src_path.read_bytes()

        # ---- modern cipher: everything except salt + nonce is encrypted ----
        cipher_cls, key_len, nonce_len = ALGORITHMS[opts.algo]
        if opts.compress:
            data = zlib.compress(data, 9)

        salt = secrets.token_bytes(SALT_LEN)
        header_nonce = secrets.token_bytes(HNONCE_LEN)
        nonce = secrets.token_bytes(nonce_len)

        # One slow KDF run -> master key -> (header key, body key)
        master = derive_key(opts.key, salt, opts.kdf, 32)

        # The real settings go INSIDE the encrypted header
        header = {"name": src_path.name, "is_dir": is_dir, "algo": opts.algo,
                  "compressed": opts.compress, "nonce": b64(nonce)}
        enc_header = AESGCM(header_key(master)).encrypt(
            header_nonce, pack_header_block(header), salt)

        # The data is bound to the header: AAD = everything written before it
        prefix = salt + header_nonce + enc_header
        body = cipher_cls(body_key(master, key_len)).encrypt(nonce, data, prefix)

        # Output name: random (hides the original name) or NAME.encx
        name = (secrets.token_hex(8) if opts.hide_name else src_path.name) + EXTENSION
        out_path = unique_path(Path(opts.out_dir) / name)
        out_path.write_bytes(prefix + body)
        return str(out_path)
    finally:
        if temp_zip and os.path.exists(temp_zip):
            os.remove(temp_zip)


def decrypt_file(src: str, password: str, out_dir: str) -> str:
    """Decrypt a modern .encx file. Returns the path of the restored file/folder."""
    blob = Path(src).read_bytes()
    if len(blob) < PREFIX_LEN:
        raise ValueError("This is not a valid modern EncryptX file (file is too small).")
    salt = blob[:SALT_LEN]
    header_nonce = blob[SALT_LEN:SALT_LEN + HNONCE_LEN]
    enc_header = blob[SALT_LEN + HNONCE_LEN:PREFIX_LEN]
    prefix, body = blob[:PREFIX_LEN], blob[PREFIX_LEN:]

    # The KDF is not stored anywhere, so try each one until the header opens.
    for kdf in KDFS:
        master = derive_key(password, salt, kdf, 32)
        try:
            header = unpack_header_block(
                AESGCM(header_key(master)).decrypt(header_nonce, enc_header, salt))
            break
        except InvalidTag:
            continue
    else:
        raise ValueError("Wrong key, or this is not a modern EncryptX file, "
                         "or the file is damaged.")

    cipher_cls, key_len, _ = ALGORITHMS[header["algo"]]
    nonce = base64.b64decode(header["nonce"])
    try:
        data = cipher_cls(body_key(master, key_len)).decrypt(nonce, body, prefix)
    except (InvalidTag, InvalidSignature):
        raise ValueError("The file is damaged or was modified.")
    if header["compressed"]:
        data = zlib.decompress(data)

    out_path = unique_path(Path(out_dir) / header["name"])
    if header["is_dir"]:
        # data is a zip file -> extract it into a folder
        tmp = Path(tempfile.gettempdir()) / ("encx_" + secrets.token_hex(4) + ".zip")
        tmp.write_bytes(data)
        try:
            shutil.unpack_archive(str(tmp), str(out_path), "zip")
        finally:
            tmp.unlink(missing_ok=True)
    else:
        out_path.write_bytes(data)
    return str(out_path)



# ----------------------------------------------------------------------------
# Dark theme helpers
# ----------------------------------------------------------------------------
def apply_dark_titlebar(window: tk.Tk):
    """Make the Windows title bar dark (Windows 10/11). Ignored elsewhere."""
    try:
        import ctypes
        window.update()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def setup_style(root: tk.Tk):
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=BG, foreground=FG, font=("Segoe UI", 10))
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Dim.TLabel", foreground=FG_DIM)
    style.configure("Status.TLabel", foreground=FG_DIM)

    style.configure("TLabelframe", background=BG, bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=BG, foreground=FG)

    style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                    insertcolor=FG, bordercolor=BORDER, lightcolor=BORDER,
                    darkcolor=BORDER, padding=5)
    style.map("TEntry", bordercolor=[("focus", ACCENT)],
              lightcolor=[("focus", ACCENT)], darkcolor=[("focus", ACCENT)])

    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                    foreground=FG, arrowcolor=FG, bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER, padding=4)
    style.map("TCombobox",
              fieldbackground=[("readonly", PANEL)],
              foreground=[("readonly", FG)],
              selectbackground=[("readonly", PANEL)],
              selectforeground=[("readonly", FG)])
    root.option_add("*TCombobox*Listbox.background", PANEL)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)

    style.configure("TCheckbutton", background=BG, foreground=FG,
                    indicatorbackground=PANEL, indicatorforeground=FG)
    style.map("TCheckbutton", background=[("active", BG)],
              indicatorbackground=[("selected", ACCENT)])

    style.configure("TButton", background=PANEL, foreground=FG,
                    bordercolor=BORDER, padding=(14, 6))
    style.map("TButton", background=[("active", BORDER)])

    style.configure("Accent.TButton", background=ACCENT, foreground="white",
                    bordercolor=ACCENT, padding=(22, 6))
    style.map("Accent.TButton", background=[("active", ACCENT_HOVER)])

    style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL,
                    bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)


def set_visible(widgets, visible: bool):
    """Show / hide grid widgets (their position is remembered)."""
    for w in widgets:
        if visible:
            w.grid()
        else:
            w.grid_remove()


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
class CryptoWindow(tk.Tk):
    """One window used for both modes: 'encrypt' and 'decrypt'."""

    def __init__(self, mode: str, target: str):
        super().__init__()
        self.mode = mode
        self.target = target
        self.results = queue.Queue()    # worker thread -> GUI messages
        self.title("Encrypt - EncryptX" if mode == "encrypt" else "Decrypt - EncryptX")
        self.resizable(False, False)
        setup_style(self)

        # Tk variables bound to the widgets
        self.v_out = tk.StringVar(value=str(Path(target).parent))
        self.v_algo = tk.StringVar(value=AUTO if mode == "decrypt" else "AES-256-GCM")
        self.v_kdf = tk.StringVar(value=KDFS[0])
        self.v_key = tk.StringVar()
        self.v_key2 = tk.StringVar()
        self.v_hint = tk.StringVar()
        self.v_show = tk.BooleanVar(value=False)
        self.v_compress = tk.BooleanVar(value=True)
        self.v_hide_name = tk.BooleanVar(value=True)
        self.v_delete = tk.BooleanVar(value=False)
        self.v_status = tk.StringVar(value="Ready")

        self.build_ui()
        self.refresh_options()
        apply_dark_titlebar(self)
        self.center()

    # ---- layout ------------------------------------------------------------
    def combo_row(self, parent, row, text, var, values):
        """A 'label + readonly combobox' row. Returns [label, combobox]."""
        label = ttk.Label(parent, text=text)
        label.grid(row=row, column=0, sticky="w", pady=5)
        combo = ttk.Combobox(parent, textvariable=var, values=values, state="readonly")
        combo.grid(row=row, column=1, columnspan=2, sticky="ew", pady=5)
        return [label, combo]

    def build_ui(self):
        pad = {"padx": 16}
        enc = self.mode == "encrypt"

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, pady=(14, 0), **pad)
        body.columnconfigure(1, weight=1)

        # -- Source / output folder
        ttk.Label(body, text="Source:").grid(row=0, column=0, sticky="w", pady=5)
        src = ttk.Entry(body, width=54)
        src.insert(0, self.target)
        src.configure(state="readonly")
        src.grid(row=0, column=1, columnspan=2, sticky="ew", pady=5)

        ttk.Label(body, text="Output folder:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(body, textvariable=self.v_out).grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Button(body, text="...", width=3, command=self.browse_out).grid(
            row=1, column=2, padx=(6, 0))

        # -- Algorithm and key derivation
        if enc:
            _, self.cb_algo = self.combo_row(body, 2, "Algorithm:", self.v_algo,
                                             list(ALGORITHMS))
            self.kdf_widgets = self.combo_row(body, 3, "Key derivation:", self.v_kdf, KDFS)
            self.cb_algo.bind("<<ComboboxSelected>>", self.refresh_options)
        else:
            _, self.cb_algo = self.combo_row(body, 2, "Algorithm:", self.v_algo, [AUTO])
            self.cb_algo.configure(state="disabled")

        # -- Key box
        box = ttk.LabelFrame(self, text=" Key ")
        box.pack(fill="x", pady=(10, 0), **pad)
        box.columnconfigure(0, weight=1)

        ttk.Label(box, text="Enter key:").grid(
            row=0, column=0, sticky="w", padx=10, pady=(8, 0))
        self.e_key = ttk.Entry(box, textvariable=self.v_key, show="*")
        self.e_key.grid(row=1, column=0, sticky="ew", padx=10, pady=(2, 6))
        self.e_key.focus_set()

        row = 2
        self.e_key2 = None
        self.btn_gen = None
        if enc:
            ttk.Label(box, text="Re-enter key:").grid(row=row, column=0, sticky="w", padx=10)
            self.e_key2 = ttk.Entry(box, textvariable=self.v_key2, show="*")
            self.e_key2.grid(row=row + 1, column=0, sticky="ew", padx=10, pady=(2, 6))
            self.btn_gen = ttk.Button(box, text="Generate", command=self.generate_key)
            self.btn_gen.grid(row=1, column=1, padx=(0, 10))
            row += 2

        ttk.Label(box, textvariable=self.v_hint, style="Dim.TLabel",
                  wraplength=430, justify="left").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 4))
        ttk.Checkbutton(box, text="Show key", variable=self.v_show,
                        command=self.toggle_show).grid(
            row=row + 1, column=0, sticky="w", padx=10, pady=(0, 8))

        # -- Options box
        opt = ttk.LabelFrame(self, text=" Options ")
        opt.pack(fill="x", pady=(10, 0), **pad)
        self.chk_compress = self.chk_hide = None
        if enc:
            self.chk_compress = ttk.Checkbutton(
                opt, text="Compress before encrypting", variable=self.v_compress)
            self.chk_compress.grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2))
            self.chk_hide = ttk.Checkbutton(
                opt, text="Hide file name (random name for the .encx file)",
                variable=self.v_hide_name)
            self.chk_hide.grid(row=1, column=0, sticky="w", padx=10, pady=(2, 2))
        ttk.Checkbutton(
            opt,
            text="Delete original after encryption" if enc
            else "Delete encrypted file after decryption",
            variable=self.v_delete,
        ).grid(row=2, column=0, sticky="w", padx=10, pady=(2, 8) if enc else (8, 8))

        # -- Status + buttons
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", pady=(12, 0), **pad)
        self.lbl_status = ttk.Label(self, textvariable=self.v_status,
                                    style="Status.TLabel", wraplength=470)
        self.lbl_status.pack(anchor="w", padx=16, pady=(4, 0))

        buttons = ttk.Frame(self)
        buttons.pack(fill="x", pady=14, **pad)
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        self.btn_ok = ttk.Button(
            buttons, text="Encrypt" if enc else "Decrypt",
            style="Accent.TButton", command=self.on_ok)
        self.btn_ok.pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.destroy())

    # ---- algorithm options -------------------------------------------------
    def refresh_options(self, event=None):
        self.v_hint.set(
            "Modern encrypted .encx file. The algorithm and original file name "
            "are stored in the encrypted header. Enter the same key used for encryption."
            if self.mode == "decrypt" else
            "Use a strong, unique key and save it safely. The file name and algorithm "
            "are stored inside the encrypted header."
        )

    # ---- small helpers -----------------------------------------------------
    def center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"+{x}+{y}")

    def browse_out(self):
        folder = filedialog.askdirectory(initialdir=self.v_out.get())
        if folder:
            self.v_out.set(folder)

    def toggle_show(self):
        ch = "" if self.v_show.get() else "*"
        self.e_key.configure(show=ch)
        if self.e_key2:
            self.e_key2.configure(show=ch)

    def generate_key(self):
        key = secrets.token_urlsafe(24)
        self.v_key.set(key)
        self.v_key2.set(key)
        self.v_show.set(True)
        self.toggle_show()
        self.set_status("Random key generated - save it somewhere safe!", OK)

    def set_status(self, text, color=FG_DIM):
        self.v_status.set(text)
        self.lbl_status.configure(foreground=color)

    # ---- actions -----------------------------------------------------------
    def on_ok(self):
        key = self.v_key.get()
        if not key:
            return self.set_status("Please enter a key.", ERROR)
        if self.mode == "encrypt" and key != self.v_key2.get():
            return self.set_status("Keys do not match.", ERROR)
        if not os.path.isdir(self.v_out.get()):
            return self.set_status("Output folder does not exist.", ERROR)

        # Read ALL widget values here (GUI thread). The background thread must
        # never touch Tk variables.
        out_dir = self.v_out.get()
        selected_algo = self.v_algo.get()

        # Build the job, then run it in a background thread.
        if self.mode == "encrypt":
            opts = EncryptOptions(
                algo=self.v_algo.get(), key=key, out_dir=self.v_out.get(),
                kdf=self.v_kdf.get(), compress=self.v_compress.get(),
                hide_name=self.v_hide_name.get())
            job = lambda: encrypt_path(self.target, opts)
        else:
            job = lambda: decrypt_file(self.target, key, out_dir)
        delete_source = self.v_delete.get()

        self.btn_ok.state(["disabled"])
        self.progress.start(12)
        self.set_status("Working...")
        threading.Thread(target=self.worker, args=(job, delete_source), daemon=True).start()
        self.after(100, self.poll)

    def worker(self, job, delete_source):
        """Runs in a background thread so the window does not freeze."""
        try:
            result = job()
            if delete_source:
                delete_path(self.target)
            self.results.put((True, result))
        except Exception as exc:                 # show any error in the window
            self.results.put((False, str(exc)))

    def poll(self):
        """Check (from the GUI thread) whether the worker has finished."""
        try:
            ok, message = self.results.get_nowait()
        except queue.Empty:
            self.after(100, self.poll)
            return
        self.progress.stop()
        self.btn_ok.state(["!disabled"])
        if ok:
            messagebox.showinfo(APP_NAME, "Finished successfully:\n" + message)
            self.destroy()
        else:
            self.set_status(message, ERROR)


class InstallerWindow(tk.Tk):
    """Small window shown when you start the program with no arguments."""

    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.resizable(False, False)
        setup_style(self)
        ttk.Label(self, text="Windows context menu integration",
                  font=("Segoe UI", 12, "bold")).pack(padx=24, pady=(20, 4))
        ttk.Label(self, text="Adds  EncryptX > Encrypt / Decrypt  to the right-click menu.",
                  style="Dim.TLabel").pack(padx=24)
        ttk.Label(self, text="Windows 11: look under \"Show more options\".",
                  style="Dim.TLabel").pack(padx=24, pady=(2, 0))
        row = ttk.Frame(self)
        row.pack(pady=20)
        ttk.Button(row, text="Install", style="Accent.TButton",
                   command=lambda: self.run(install)).pack(side="left", padx=6)
        ttk.Button(row, text="Uninstall",
                   command=lambda: self.run(uninstall)).pack(side="left", padx=6)
        apply_dark_titlebar(self)

    def run(self, fn):
        try:
            fn()
            messagebox.showinfo(APP_NAME, "Done.")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))


def show_error(message: str):
    """Message box without any other window (used before the main window)."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(APP_NAME, message)
    root.destroy()


# ----------------------------------------------------------------------------
# Windows context-menu registration  (HKEY_CURRENT_USER => no admin needed)
#
# Registry layout of a cascading ("group") menu:
#
#   ...\shell\EncryptX                 MUIVerb = "EncryptX", SubCommands = ""
#   ...\shell\EncryptX\shell\01_encrypt   MUIVerb = "Encrypt"
#   ...\shell\EncryptX\shell\01_encrypt\command   (Default) = <command line>
#   ...\shell\EncryptX\shell\02_decrypt   MUIVerb = "Decrypt"
#   ...
# ----------------------------------------------------------------------------
# Encrypt is always shown (every file type + folders).
# True  -> "Decrypt" is shown only for .encx files (uses an Explorer filter).
# False -> "Decrypt" is shown for every file (use this if the filter does not
#          work on your Windows version).
SHOW_DECRYPT_ONLY_FOR_ENCX = True

FILE_GROUP = r"Software\Classes\*\shell\EncryptX"            # right-click on a file
FOLDER_GROUP = r"Software\Classes\Directory\shell\EncryptX"  # right-click on a folder

# Keys created by the first version of this tool - removed automatically.
LEGACY_KEYS = [
    r"Software\Classes\*\shell\EncryptX_Encrypt",
    r"Software\Classes\Directory\shell\EncryptX_Encrypt",
    r"Software\Classes\SystemFileAssociations\.encx\shell\EncryptX_Decrypt",
]


def launcher_command(mode: str) -> str:
    """The command line Windows runs when you click the menu item."""
    if getattr(sys, "frozen", False):               # running as EncryptX.exe
        return f'"{sys.executable}" {mode} "%1"'
    pyw = Path(sys.executable).with_name("pythonw.exe")   # no black console window
    python = pyw if pyw.exists() else Path(sys.executable)
    return f'"{python}" "{os.path.abspath(__file__)}" {mode} "%1"'


def menu_icon() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}",0'
    return "shell32.dll,48"


def _set_value(path: str, name: str, value: str):
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def _delete_tree(path: str):
    """Delete a registry key together with all its sub-keys."""
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


def _refresh_explorer():
    try:
        import ctypes
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except Exception:
        pass


def install():
    uninstall(refresh=False)                        # start clean
    groups = [(FILE_GROUP, ["encrypt", "decrypt"]),
              (FOLDER_GROUP, ["encrypt"])]          # folders can only be encrypted
    for group, modes in groups:
        _set_value(group, "MUIVerb", "EncryptX")    # text of the group
        _set_value(group, "SubCommands", "")        # empty value = "this is a submenu"
        _set_value(group, "Icon", menu_icon())
        for number, mode in enumerate(modes, 1):
            item = f"{group}\\shell\\{number:02d}_{mode}"   # 01_encrypt, 02_decrypt
            _set_value(item, "MUIVerb", mode.capitalize())
            if mode == "decrypt" and SHOW_DECRYPT_ONLY_FOR_ENCX:
                _set_value(item, "AppliesTo", f'System.FileExtension:="{EXTENSION}"')
            _set_value(item + r"\command", "", launcher_command(mode))
    _refresh_explorer()


def uninstall(refresh: bool = True):
    for path in (FILE_GROUP, FOLDER_GROUP, *LEGACY_KEYS):
        _delete_tree(path)
    if refresh:
        _refresh_explorer()


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------
def main():
    # Sharp text on high-DPI screens
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    args = sys.argv[1:]

    if not args:
        InstallerWindow().mainloop()
    elif args[0] == "install":
        install()
    elif args[0] == "uninstall":
        uninstall()
    elif args[0] == "encrypt" and len(args) >= 2:
        CryptoWindow("encrypt", args[1]).mainloop()
    elif args[0] == "decrypt" and len(args) >= 2:
        CryptoWindow("decrypt", args[1]).mainloop()
    else:
        show_error("Usage:\n  encrypt <path>\n  decrypt <path.encx>\n  install | uninstall")


if __name__ == "__main__":
    main()