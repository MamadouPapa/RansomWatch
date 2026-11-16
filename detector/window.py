"""Time-based sliding window counter."""
from __future__ import annotations

from collections import deque


class SlidingWindow:
    """Counts events whose timestamp is within the last ``length_s`` seconds."""

    def __init__(self, length_s: float) -> None:
        if length_s <= 0:
            raise ValueError("window length must be > 0")
        self._length_s = length_s
        self._events: deque = deque()

    def add(self, now: float, payload: object = None) -> int:
        """Record one event at ``now`` and return the count inside the window."""
        self._events.append((now, payload))
        return self.count(now)

    def count(self, now: float) -> int:
        self._expire(now)
        return len(self._events)

    def payloads(self, now: float) -> tuple:
        self._expire(now)
        return tuple(payload for _ts, payload in self._events)

    def _expire(self, now: float) -> None:
        cutoff = now - self._length_s
        while self._events and self._events[0][0] <= cutoff:
            self._events.popleft()
