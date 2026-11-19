"""Launcher used for development and by PyInstaller (keeps `src/` layout importable)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from encryptx.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
