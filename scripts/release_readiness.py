#!/usr/bin/env python3
"""Compatibility entry point for the renamed release-check implementation."""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.release_check import *  # noqa: F403
from scripts.release_check import main


if __name__ == "__main__":
    raise SystemExit(main())
