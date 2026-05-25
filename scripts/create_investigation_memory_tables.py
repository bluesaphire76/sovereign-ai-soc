#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import engine
from models import Base


def main() -> int:
    Base.metadata.create_all(bind=engine)
    print("Investigation memory tables ensured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
