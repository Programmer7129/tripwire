"""Test configuration for the Tripwire harness.

The harness modules use flat, sibling imports (``import aggregate``), so
``harness/`` goes on ``sys.path``. ``REPO`` and ``RESULTS`` locate the committed
evidence for the published-number regression tests.

Every test in this suite runs with no network, no Docker, no API key and no GPU.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HARNESS = REPO / "harness"
RESULTS = REPO / "results"

if str(HARNESS) not in sys.path:
    sys.path.insert(0, str(HARNESS))


def read_result(name: str) -> dict:
    """Load a committed record from ``results/``."""
    with open(RESULTS / name) as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def results_dir() -> Path:
    return RESULTS
