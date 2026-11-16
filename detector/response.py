"""Safe, best-effort response actions.

Default behaviour of ``--respond`` is observational only:
  * append an incident record (alert + suspect processes) to a JSONL file;
  * print the suspect PIDs on stderr.

Signals are only sent when the operator explicitly passes ``--suspend``
(SIGSTOP, keeps the process and its AES key in memory for forensics) or
``--kill`` (SIGKILL). Both are LAB-ONLY: attribution through /proc is racy
and may point at an innocent process (editor, backup agent, indexer).
"""
from __future__ import annotations

import json
import os
import signal
import sys
from dataclasses import asdict, dataclass
from typing import Iterable, List, Optional, Tuple

import constants as C

CONTAIN_NONE = "none"
CONTAIN_SUSPEND = "suspend"
CONTAIN_KILL = "kill"
CONTAIN_SIGNALS = {CONTAIN_SUSPEND: signal.SIGSTOP, CONTAIN_KILL: signal.SIGKILL}


@dataclass(frozen=True)
class SuspectProcess:
    pid: int
    comm: str
    exe: str
    evidence: str  # path under the watched root that linked the PID to it


def proc_available(proc_root: str = C.PROC_ROOT) -> bool:
    return sys.platform.startswith("linux") and os.path.isdir(proc_root)


def find_suspect_pids(watched_root: str,
                      proc_root: str = C.PROC_ROOT) -> Tuple[SuspectProcess, ...]:
    """PIDs whose cwd or an open file descriptor lies under ``watched_root``."""
    if not proc_available(proc_root):
        return ()
    root = os.path.realpath(watched_root)
    own = {os.getpid(), os.getppid()}
    suspects: List[SuspectProcess] = []
    for entry in _list_pids(proc_root):
        if entry in own or entry <= C.PROTECTED_PID_MAX:
            continue
        evidence = _evidence_for(os.path.join(proc_root, str(entry)), root)
        if evidence is not None:
            suspects.append(_describe(proc_root, entry, evidence))
    return tuple(suspects)


def _list_pids(proc_root: str) -> List[int]:
    try:
        return [int(n) for n in os.listdir(proc_root) if n.isdigit()]
    except OSError as error:
        print(f"[ransomwatch] cannot list {proc_root}: {error}", file=sys.stderr)
        return []


def _evidence_for(proc_dir: str, root: str) -> Optional[str]:
    candidates = [os.path.join(proc_dir, "cwd")]
    try:
        fd_dir = os.path.join(proc_dir, "fd")
        candidates += [os.path.join(fd_dir, fd) for fd in os.listdir(fd_dir)]
    except OSError:
        pass  # process exited or belongs to another user: expected, skip it
    for link in candidates:
        target = _readlink(link)
        if target and (target == root or target.startswith(root + os.sep)):
            return target
    return None


def _readlink(link: str) -> Optional[str]:
    try:
        return os.readlink(link)
    except OSError:
        return None


def _describe(proc_root: str, pid: int, evidence: str) -> SuspectProcess:
    base = os.path.join(proc_root, str(pid))
    comm = _read_text(os.path.join(base, "comm")) or "?"
    exe = _readlink(os.path.join(base, "exe")) or "?"
    return SuspectProcess(pid, comm, exe, evidence)


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def contain(suspects: Iterable[SuspectProcess], mode: str) -> List[dict]:
    """Send the containment signal (if any) and report what happened."""
    if mode == CONTAIN_NONE:
        return []
    sig = CONTAIN_SIGNALS[mode]
    results = []
    for proc in suspects:
        try:
            os.kill(proc.pid, sig)
            results.append({"pid": proc.pid, "action": mode, "ok": True})
        except OSError as error:
            results.append({"pid": proc.pid, "action": mode, "ok": False,
                            "error": error.strerror})
    return results


def write_incident(path: str, alert: dict, suspects: Tuple[SuspectProcess, ...],
                   actions: List[dict]) -> None:
    record = {
        "alert": alert,
        "suspects": [asdict(s) for s in suspects],
        "pid_lookup": "proc" if proc_available() else "unavailable (non-Linux)",
        "actions": actions,
    }
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as error:
        print(f"[ransomwatch] cannot write incident file {path}: {error}",
              file=sys.stderr)
