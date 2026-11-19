# EncryptX

Encrypt / decrypt files and folders, and calculate checksums - from the Windows
right-click menu or from a small drag & drop window.

```
EncryptX  >  Encrypt     files + folders        -> compact Encrypt window
          >  Decrypt     .encx files            -> compact Decrypt window
          >  Checksum    files + folders        -> compact Checksum window
EncryptX.exe                                    -> full window (Encrypt / Decrypt tabs, drag & drop)
```

* 9 modern algorithms (AES-GCM, ChaCha20-Poly1305, OCB3, CCM, AES/Camellia + HMAC)
* Streaming: constant memory (~1 MiB) for any file size, no temporary files
* The `.encx` file looks like random data: name, algorithm and settings are encrypted
* Optional end-to-end checksum: stored before encryption, verified after decryption
* Checksum window: paste a hash, the matching algorithm turns green (11 algorithms, one read)
* Several selected files open in ONE window

## Layout
```
src/encryptx/
    app.py                       entry point / command line
    crypto/modern.py             streaming authenticated encryption
    core/file_operations.py      encrypt, decrypt, checksum (no GUI)
    gui/styles.py                dark flat theme (QSS) + icons
    gui/widgets.py               flat buttons, source list, progress, hash boxes ...
    gui/forms.py                 Encrypt / Decrypt option panels
    gui/jobs.py                  background thread + shared run controller
    gui/main_window.py           the full window (EncryptX.exe)
    gui/dialogs.py               the compact right-click windows
    platform/windows_context_menu.py   Explorer menu (development helper)
    platform/single_instance.py        many selected files -> one window
assets/                          logo (icon.ico / icon.png) and .encx file icon
installer/EncryptX.iss           Inno Setup script (installs + writes the registry keys)
tests/                           pytest (core + headless GUI tests)
```

## Run from source
```
pip install -r requirements.txt
python run.py                      # full window
python run.py encrypt  "C:\path\file.txt"
python run.py checksum "C:\path\folder"
python run.py install-menu         # development only; end users use the installer
```
Run the package from `src/` (`python -m encryptx`), never `python src/encryptx/app.py`:
the sub-package named `platform` would shadow Python's standard `platform` module.

## Build the installer
Needs Python 3.9+ and [Inno Setup 6.3+](https://jrsoftware.org/isdl.php).
```
build.bat      ->  dist\EncryptX-Setup-2.0.0.exe
```
Per-user install (no admin). Uninstalling removes every registry key.

## Tests
```
pip install pytest
pytest            # GUI tests run headless (QT_QPA_PLATFORM=offscreen)
```
