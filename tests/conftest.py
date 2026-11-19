import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")          # GUI tests need no screen
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
