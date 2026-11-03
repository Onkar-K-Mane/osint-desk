import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# TestClient sends Host: testserver; strict-host behavior is tested explicitly.
import os

os.environ.setdefault("OSINT_STRICT_HOSTS", "0")
