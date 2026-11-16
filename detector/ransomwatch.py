#!/usr/bin/env python3
"""RansomWatch - behavioural ransomware detector (polling, stdlib only).

Usage:
    python3 detector/ransomwatch.py /path/to/watch [options]

Alerts are written to stdout as JSON lines (and optionally to --output).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from typing import Callable, Optional, TextIO, Tuple

import constants as C
import response
from engine import Alert, DetectionEngine, DetectorConfig
from snapshot import diff_snapshots, take_snapshot

EXIT_OK = 0
EXIT_IO_ERROR = 1


class Responder:
    """Applies --respond actions to alerts at or above a severity."""

    def __init__(self, watched_root: str, incident_file: str,
                 min_severity: str, contain_mode: str) -> None:
        self._root = watched_root
        self._incident_file = incident_file
        self._min_rank = C.SEVERITY_ORDER.index(min_severity)
        self._mode = contain_mode
        self._handled_pids: frozenset = frozenset()

    def handle(self, alert: Alert) -> None:
        if C.SEVERITY_ORDER.index(alert.severity) < self._min_rank:
            return
        suspects = response.find_suspect_pids(self._root)
        fresh = tuple(s for s in suspects if s.pid not in self._handled_pids)
        actions = response.contain(fresh, self._mode)
        self._handled_pids = self._handled_pids | {s.pid for s in fresh}
        response.write_incident(self._incident_file, alert.to_dict(), suspects, actions)
        self._report(alert, suspects)

    def _report(self, alert: Alert, suspects) -> None:
        if not response.proc_available():
            print(f"[respond] {alert.rule_id}: PID lookup unavailable (no /proc)",
                  file=sys.stderr)
            return
        pids = ", ".join(f"{s.pid}({s.comm})" for s in suspects) or "none found"
        print(f"[respond] {alert.rule_id}: suspect PIDs: {pids}", file=sys.stderr)


class Monitor:
    """Poll loop: snapshot -> diff -> engine -> sinks."""

    def __init__(self, root: str, engine: DetectionEngine,
                 sinks: Tuple[TextIO, ...] = (sys.stdout,),
                 responder: Optional[Responder] = None,
                 exclude: frozenset = frozenset(),
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._root, self._engine, self._sinks = root, engine, sinks
        self._responder, self._exclude, self._clock = responder, exclude, clock
        self._snapshot = take_snapshot(root, exclude)
        engine.seed(self._snapshot)

    def step(self) -> Tuple[Alert, ...]:
        current = take_snapshot(self._root, self._exclude)
        changes = diff_snapshots(self._snapshot, current)
        self._snapshot = current
        alerts = self._engine.process(changes, self._clock())
        for alert in alerts:
            self._emit(alert)
        return alerts

    def run(self, interval_s: float, duration_s: Optional[float] = None,
            stop: Optional[threading.Event] = None) -> None:
        stop = stop or threading.Event()
        deadline = None if duration_s is None else self._clock() + duration_s
        while not stop.is_set():
            if deadline is not None and self._clock() >= deadline:
                return
            stop.wait(interval_s)
            self.step()

    def _emit(self, alert: Alert) -> None:
        line = json.dumps(alert.to_dict(), ensure_ascii=False)
        for sink in self._sinks:
            sink.write(line + "\n")
            sink.flush()
        if self._responder is not None:
            self._responder.handle(alert)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="RansomWatch behavioural detector")
    p.add_argument("path", help="directory tree to monitor")
    p.add_argument("--interval", type=float, default=C.DEFAULT_POLL_INTERVAL_S,
                   help="poll interval in seconds (default %(default)s)")
    p.add_argument("--duration", type=float, default=None,
                   help="stop after N seconds (default: run forever)")
    p.add_argument("--output", help="also append JSON alerts to this file")
    g = p.add_argument_group("thresholds")
    g.add_argument("--burst-threshold", type=int, default=C.DEFAULT_BURST_THRESHOLD)
    g.add_argument("--burst-window", type=float, default=C.DEFAULT_BURST_WINDOW_S)
    g.add_argument("--entropy-threshold", type=float, default=C.DEFAULT_ENTROPY_THRESHOLD)
    g.add_argument("--entropy-min-size", type=int, default=C.DEFAULT_ENTROPY_MIN_SIZE)
    g.add_argument("--entropy-jump", type=float, default=C.DEFAULT_ENTROPY_JUMP)
    g.add_argument("--archive-window", type=float, default=C.DEFAULT_ARCHIVE_WINDOW_S)
    g.add_argument("--archive-delete-threshold", type=int,
                   default=C.DEFAULT_ARCHIVE_DELETE_THRESHOLD)
    g.add_argument("--swap-threshold", type=int, default=C.DEFAULT_SWAP_THRESHOLD)
    g.add_argument("--swap-window", type=float, default=C.DEFAULT_SWAP_WINDOW_S)
    r = p.add_argument_group("response (safe by default)")
    r.add_argument("--respond", action="store_true",
                   help="write incident file + print suspect PIDs (no signal)")
    r.add_argument("--incident-file", default=C.DEFAULT_INCIDENT_FILE)
    r.add_argument("--respond-min-severity", choices=C.SEVERITY_ORDER,
                   default=C.DEFAULT_RESPOND_MIN_SEVERITY)
    contain = r.add_mutually_exclusive_group()
    contain.add_argument("--suspend", action="store_true",
                         help="LAB ONLY: SIGSTOP suspect PIDs (requires --respond)")
    contain.add_argument("--kill", action="store_true",
                         help="LAB ONLY: SIGKILL suspect PIDs (requires --respond)")
    return p


def config_from_args(args: argparse.Namespace) -> DetectorConfig:
    return DetectorConfig(
        burst_threshold=args.burst_threshold, burst_window_s=args.burst_window,
        entropy_threshold=args.entropy_threshold,
        entropy_min_size=args.entropy_min_size, entropy_jump=args.entropy_jump,
        archive_window_s=args.archive_window,
        archive_delete_threshold=args.archive_delete_threshold,
        swap_threshold=args.swap_threshold, swap_window_s=args.swap_window)


def contain_mode(args: argparse.Namespace) -> str:
    if args.kill:
        return response.CONTAIN_KILL
    if args.suspend:
        return response.CONTAIN_SUSPEND
    return response.CONTAIN_NONE


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        parser.error(f"not a directory: {root}")
    if (args.kill or args.suspend) and not args.respond:
        parser.error("--kill/--suspend require --respond")
    try:
        cfg = config_from_args(args)
    except ValueError as error:
        parser.error(str(error))
    return _run(args, root, cfg)


def _run(args: argparse.Namespace, root: str, cfg: DetectorConfig) -> int:
    exclude = frozenset(os.path.abspath(p) for p in (args.output, args.incident_file) if p)
    responder = (Responder(root, args.incident_file, args.respond_min_severity,
                           contain_mode(args)) if args.respond else None)
    try:
        out = open(args.output, "a", encoding="utf-8") if args.output else None
    except OSError as error:
        print(f"[ransomwatch] cannot open output file: {error}", file=sys.stderr)
        return EXIT_IO_ERROR
    sinks = (sys.stdout,) + ((out,) if out else ())
    print(f"[ransomwatch] watching {root} every {args.interval}s", file=sys.stderr)
    try:
        Monitor(root, DetectionEngine(cfg), sinks, responder, exclude).run(
            args.interval, args.duration)
    except KeyboardInterrupt:
        print("[ransomwatch] stopped", file=sys.stderr)
    finally:
        if out:
            out.close()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
