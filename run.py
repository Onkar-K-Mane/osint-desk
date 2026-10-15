#!/usr/bin/env python3
"""Start OSINT Desk. Works locally, in the live preview, and in Google Colab."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osint.config import DEFAULT_HOST, DEFAULT_PORT, load_secrets, ensure_data_dir


def main() -> None:
    ensure_data_dir()
    load_secrets()
    host = os.environ.get("OSINT_HOST", DEFAULT_HOST)
    port = int(os.environ.get("OSINT_PORT", str(DEFAULT_PORT)))
    import uvicorn

    uvicorn.run("osint.app:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
