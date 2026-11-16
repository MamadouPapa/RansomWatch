"""Detection engine: turns file changes into alerts.

Each rule is a small object with ``on_change(change, now) -> list[Alert]``.
``now`` is a monotonic float (seconds) so the rules can be unit-tested with a
fake clock; the wall-clock timestamp of an alert comes from ``wall_clock``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

import constants as C
from entropy import file_entropy
from notes import match_ransom_note
from snapshot import CREATED, DELETED, MODIFIED, FileChange, Snapshot
from window import SlidingWindow

EntropyReader = Callable[[str], Optional[float]]
WallClock = Callable[[], str]


@dataclass(frozen=True)
class DetectorConfig:
    burst_threshold: int = C.DEFAULT_BURST_THRESHOLD
    burst_window_s: float = C.DEFAULT_BURST_WINDOW_S
    entropy_threshold: float = C.DEFAULT_ENTROPY_THRESHOLD
    entropy_min_size: int = C.DEFAULT_ENTROPY_MIN_SIZE
    entropy_jump: float = C.DEFAULT_ENTROPY_JUMP
    archive_window_s: float = C.DEFAULT_ARCHIVE_WINDOW_S
    archive_delete_threshold: int = C.DEFAULT_ARCHIVE_DELETE_THRESHOLD
    swap_threshold: int = C.DEFAULT_SWAP_THRESHOLD
    swap_window_s: float = C.DEFAULT_SWAP_WINDOW_S

    def __post_init__(self) -> None:
        positive = ("burst_threshold", "burst_window_s", "archive_window_s",
                    "archive_delete_threshold", "swap_threshold", "swap_window_s")
        for name in positive:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0")
        if not 0.0 < self.entropy_threshold <= C.BITS_PER_BYTE_MAX:
            raise ValueError("entropy_threshold must be in (0, 8]")


@dataclass(frozen=True)
class Alert:
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: str
    mitre_name: str
    details: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "mitre": {"technique_id": self.mitre_technique,
                      "technique_name": self.mitre_name},
            "details": dict(self.details),
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def make_alert(rule_id: str, details: Dict[str, object], wall_clock: WallClock) -> Alert:
    name, severity, technique, technique_name = C.RULES[rule_id]
    return Alert(wall_clock(), rule_id, name, severity, technique, technique_name,
                 dict(details))


def _extension(path: str) -> str:
    return os.path.splitext(path)[1].lower()


class BurstRule:
    """RW-001: too many creations/modifications inside a sliding window."""

    def __init__(self, cfg: DetectorConfig, wall_clock: WallClock) -> None:
        self._cfg, self._clock = cfg, wall_clock
        self._window = SlidingWindow(cfg.burst_window_s)
        self._last_alert: Optional[float] = None

    def on_change(self, change: FileChange, now: float) -> List[Alert]:
        if change.kind not in (CREATED, MODIFIED):
            return []
        count = self._window.add(now, change.path)
        if count < self._cfg.burst_threshold or self._in_cooldown(now):
            return []
        self._last_alert = now
        recent = self._window.payloads(now)[-C.BURST_SAMPLE_PATHS:]
        return [make_alert("RW-001", {
            "events_in_window": count,
            "window_seconds": self._cfg.burst_window_s,
            "threshold": self._cfg.burst_threshold,
            "sample_paths": list(recent),
        }, self._clock)]

    def _in_cooldown(self, now: float) -> bool:
        return (self._last_alert is not None
                and now - self._last_alert < self._cfg.burst_window_s)


class EntropyRule:
    """RW-002: newly written content looks encrypted (vs per-file baseline)."""

    def __init__(self, cfg: DetectorConfig, wall_clock: WallClock,
                 reader: EntropyReader) -> None:
        self._cfg, self._clock, self._read = cfg, wall_clock, reader
        self._baseline: Dict[str, float] = {}

    def seed(self, snapshot: Snapshot) -> None:
        for path, state in snapshot.items():
            if self._is_scored(path, state.size):
                value = self._read(path)
                if value is not None:
                    self._baseline[path] = value

    def on_change(self, change: FileChange, now: float) -> List[Alert]:
        if change.kind == DELETED:
            return []
        if not self._is_scored(change.path, change.size):
            return []
        value = self._read(change.path)
        if value is None:
            return []
        reference = self._reference_entropy(change.path)
        self._baseline[change.path] = value
        if not self._is_suspicious(value, reference):
            return []
        return [make_alert("RW-002", {
            "path": change.path,
            "change": change.kind,
            "entropy_bits_per_byte": round(value, 3),
            "baseline_bits_per_byte": None if reference is None else round(reference, 3),
            "threshold": self._cfg.entropy_threshold,
        }, self._clock)]

    def _reference_entropy(self, path: str) -> Optional[float]:
        """Previous entropy of the file, or of the original it replaces
        (``notes.txt`` for ``notes.txt.enc``)."""
        if path in self._baseline:
            return self._baseline[path]
        stem = os.path.splitext(path)[0]
        return self._baseline.get(stem)

    def _is_suspicious(self, value: float, reference: Optional[float]) -> bool:
        if value < self._cfg.entropy_threshold:
            return False
        return reference is None or value - reference >= self._cfg.entropy_jump

    def _is_scored(self, path: str, size: int) -> bool:
        return (size >= self._cfg.entropy_min_size
                and _extension(path) not in C.NATURALLY_COMPRESSED_EXTENSIONS)


class RansomNoteRule:
    """RW-003: a file whose name looks like a ransom note appears."""

    def __init__(self, cfg: DetectorConfig, wall_clock: WallClock) -> None:
        self._clock = wall_clock

    def on_change(self, change: FileChange, now: float) -> List[Alert]:
        if change.kind != CREATED:
            return []
        pattern = match_ransom_note(os.path.basename(change.path))
        if pattern is None:
            return []
        return [make_alert("RW-003", {"path": change.path, "pattern": pattern},
                           self._clock)]


class ArchiveThenDeleteRule:
    """RW-004: an archive is created, then many files below its folder vanish."""

    def __init__(self, cfg: DetectorConfig, wall_clock: WallClock) -> None:
        self._cfg, self._clock = cfg, wall_clock
        self._archives: Dict[str, Tuple[float, int]] = {}  # path -> (t, deletions)

    def on_change(self, change: FileChange, now: float) -> List[Alert]:
        self._expire(now)
        if change.kind == CREATED and _extension(change.path) in C.ARCHIVE_EXTENSIONS:
            self._archives = {**self._archives, change.path: (now, 0)}
            return []
        if change.kind != DELETED:
            return []
        return [a for a in (self._count_deletion(arc, change.path)
                            for arc in tuple(self._archives)) if a is not None]

    def _count_deletion(self, archive: str, deleted: str) -> Optional[Alert]:
        created_at, deletions = self._archives[archive]
        if deleted == archive or not _is_below(deleted, os.path.dirname(archive)):
            return None
        deletions += 1
        self._archives = {**self._archives, archive: (created_at, deletions)}
        if deletions != self._cfg.archive_delete_threshold:
            return None  # alert exactly once per archive
        return make_alert("RW-004", {
            "archive": archive,
            "deletions_after_archive": deletions,
            "window_seconds": self._cfg.archive_window_s,
            "last_deleted": deleted,
        }, self._clock)

    def _expire(self, now: float) -> None:
        self._archives = {p: v for p, v in self._archives.items()
                          if now - v[0] < self._cfg.archive_window_s}


class ExtensionSwapRule:
    """RW-005: ``X`` deleted while ``X.<new_ext>`` is created (encrypt + remove)."""

    def __init__(self, cfg: DetectorConfig, wall_clock: WallClock) -> None:
        self._cfg, self._clock = cfg, wall_clock
        self._created = SlidingWindow(cfg.swap_window_s)
        self._swaps = SlidingWindow(cfg.swap_window_s)
        self._last_alert: Optional[float] = None

    def on_change(self, change: FileChange, now: float) -> List[Alert]:
        if change.kind == CREATED:
            self._created.add(now, change.path)
            return []
        if change.kind != DELETED:
            return []
        suffix = self._replacement_suffix(change.path, now)
        if suffix is None:
            return []
        count = self._swaps.add(now, suffix)
        if count < self._cfg.swap_threshold or self._in_cooldown(now):
            return []
        self._last_alert = now
        return [make_alert("RW-005", {
            "swaps_in_window": count,
            "window_seconds": self._cfg.swap_window_s,
            "new_extensions": sorted(set(self._swaps.payloads(now))),
            "last_original": change.path,
        }, self._clock)]

    def _replacement_suffix(self, deleted: str, now: float) -> Optional[str]:
        for created in self._created.payloads(now):
            suffix = created[len(deleted):]
            if (created.startswith(deleted + ".")
                    and len(suffix) <= C.SWAP_MAX_SUFFIX_LEN
                    and suffix.count(".") == 1):
                return suffix
        return None

    def _in_cooldown(self, now: float) -> bool:
        return (self._last_alert is not None
                and now - self._last_alert < self._cfg.swap_window_s)


def _is_below(path: str, directory: str) -> bool:
    return os.path.commonpath([os.path.abspath(path), os.path.abspath(directory)]) \
        == os.path.abspath(directory)


class DetectionEngine:
    """Runs every rule on every change and collects the alerts."""

    def __init__(self, cfg: DetectorConfig = DetectorConfig(),
                 entropy_reader: EntropyReader = file_entropy,
                 wall_clock: WallClock = utc_now_iso) -> None:
        self._entropy = EntropyRule(cfg, wall_clock, entropy_reader)
        self._rules = (
            RansomNoteRule(cfg, wall_clock),
            ArchiveThenDeleteRule(cfg, wall_clock),
            ExtensionSwapRule(cfg, wall_clock),
            BurstRule(cfg, wall_clock),
            self._entropy,
        )

    def seed(self, snapshot: Snapshot) -> None:
        """Learn the entropy baseline of files present at start-up."""
        self._entropy.seed(snapshot)

    def process(self, changes, now: float) -> Tuple[Alert, ...]:
        alerts: List[Alert] = []
        for change in changes:
            for rule in self._rules:
                alerts.extend(rule.on_change(change, now))
        return tuple(alerts)
