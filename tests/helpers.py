"""Puts detector/ on sys.path so tests can import the modules directly."""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTOR_DIR = os.path.join(PROJECT_ROOT, "detector")
if DETECTOR_DIR not in sys.path:
    sys.path.insert(0, DETECTOR_DIR)


class FakeClock:
    """Fixed wall clock so alerts are deterministic in tests."""

    TIMESTAMP = "2026-11-16T00:00:00.000+00:00"

    def __call__(self) -> str:
        return self.TIMESTAMP
