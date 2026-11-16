"""Shannon entropy helpers (bits per byte)."""
from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from constants import DEFAULT_ENTROPY_SAMPLE_BYTES


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0 to 8.0).

    Plain text is usually 3.5-5 bits/byte; AES output or os.urandom() is
    close to 8 for samples of a few KiB.
    """
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data).values()
    return -sum((n / total) * math.log2(n / total) for n in counts)


def file_entropy(path: str,
                 max_bytes: int = DEFAULT_ENTROPY_SAMPLE_BYTES) -> Optional[float]:
    """Entropy of the first ``max_bytes`` of a file, or None if unreadable.

    Files can vanish or be locked between the poll and the read (that is the
    whole point of a ransomware run), so I/O errors are expected and mapped to
    None instead of crashing the monitor.
    """
    try:
        with open(path, "rb") as handle:
            return shannon_entropy(handle.read(max_bytes))
    except OSError:
        return None
