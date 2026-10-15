#!/usr/bin/env python3
"""Run OSINT Desk outside Colab — same as run.py, bind loopback by default.

  python3 run_local.py

Set OSINT_HOST / OSINT_PORT / OSINT_DATA_DIR as needed. Keys live in
$OSINT_DATA_DIR/secrets.env (or the Providers page). This process is
intentionally not tunneled; there is no login wall.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("OSINT_HOST", "127.0.0.1")
os.environ.setdefault("OSINT_PORT", "8080")

from run import main

if __name__ == "__main__":
    main()
