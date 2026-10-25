# EncryptX

EncryptX is a Windows desktop tool for encrypting and decrypting files/folders using modern cryptographic algorithms. It also adds EncryptX actions to the Windows Explorer context menu.

## Features

- Tkinter graphical interface with a dark theme.
- File and folder encryption (folders are temporarily archived before encryption).
- Authenticated encryption algorithms, including AES-GCM and ChaCha20-Poly1305.
- Scrypt or PBKDF2-SHA256 key derivation.
- Optional compression and randomized output names.
- Encrypted metadata header.
- Optional deletion of the source after a successful operation.
- Windows Explorer context-menu integration.

## Requirements

- Windows 10/11.
- Python 3.10 or newer.

## Install and run from source

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m encryptx
```

## Usage

Run `python -m encryptx` to open the installer window. Choose **Install** to add the context menu or **Uninstall** to remove it. Explorer actions open the encryption/decryption window for the selected file or folder.

You can also launch the application module directly: `python -m encryptx.app`.

## Project layout

```text
encryptx-project/
├── .github/workflows/tests.yml  # automated checks on pushes and pull requests
├── src/encryptx/
│   ├── __init__.py               # package metadata/version
│   ├── __main__.py               # enables python -m encryptx
│   └── app.py                    # GUI, encryption logic, and Windows integration
├── tests/test_package.py         # basic project-structure checks
├── .gitignore                    # files Git should not track
├── pyproject.toml                # package/build configuration
├── requirements.txt              # pip dependency list
└── README.md                     # project documentation
```

## Security notes

- Use a strong, unique password and store it in a password manager. EncryptX cannot recover a lost key.
- Do not enable source deletion until you have tested the workflow and confirmed the output can be decrypted. Keep backups of important data.
- Encryption protects file contents; it does not protect against malware or someone who can access the unlocked original files.
