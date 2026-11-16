"""Polling-based view of a directory tree: snapshot + diff.

Deliberately the same primitive as the ransomware itself (opendir + sleep):
no inotify/fanotify, so it runs unchanged on Linux and macOS.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Dict, FrozenSet, Tuple

CREATED = "created"
MODIFIED = "modified"
DELETED = "deleted"
# Creations are processed first so that "archive created, then originals
# deleted" is ordered correctly even when both land in the same poll.
KIND_ORDER = {CREATED: 0, MODIFIED: 1, DELETED: 2}


@dataclass(frozen=True)
class FileState:
    size: int
    mtime_ns: int
    inode: int


@dataclass(frozen=True)
class FileChange:
    kind: str
    path: str
    size: int


Snapshot = Dict[str, FileState]


def take_snapshot(root: str, exclude: FrozenSet[str] = frozenset()) -> Snapshot:
    """Return {absolute_path: FileState} for every regular file under root."""
    states: Snapshot = {}
    for dirpath, _dirs, files in os.walk(root, onerror=_report_walk_error):
        for name in files:
            path = os.path.join(dirpath, name)
            if path in exclude:
                continue
            state = _stat_file(path)
            if state is not None:
                states[path] = state
    return states


def diff_snapshots(old: Snapshot, new: Snapshot) -> Tuple[FileChange, ...]:
    """Compute created / modified / deleted files between two snapshots."""
    changes = [FileChange(CREATED, p, s.size) for p, s in new.items() if p not in old]
    changes += [FileChange(MODIFIED, p, s.size) for p, s in new.items()
                if p in old and s != old[p]]
    changes += [FileChange(DELETED, p, s.size) for p, s in old.items() if p not in new]
    return tuple(sorted(changes, key=lambda c: (KIND_ORDER[c.kind], c.path)))


def _stat_file(path: str):
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None  # file removed between listdir and stat
    if not os.path.isfile(path) or os.path.islink(path):
        return None
    return FileState(st.st_size, st.st_mtime_ns, st.st_ino)


def _report_walk_error(error: OSError) -> None:
    print(f"[ransomwatch] cannot read {error.filename}: {error.strerror}",
          file=sys.stderr)
