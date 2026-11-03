import sys
from pathlib import Path

import os
import tempfile

# Never touch the real data dir (SQLite, secrets) from tests. Must precede any osint import.
os.environ.setdefault("OSINT_DATA_DIR", tempfile.mkdtemp(prefix="osint-test-"))

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# TestClient sends Host: testserver; strict-host behavior is tested explicitly.
os.environ.setdefault("OSINT_STRICT_HOSTS", "0")
