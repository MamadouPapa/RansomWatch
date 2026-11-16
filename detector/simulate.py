#!/usr/bin/env python3
"""Harmless attack simulation: reproduces ProManager's *observable* file-system
behaviour on throw-away files in a temporary directory, with RansomWatch
watching. Nothing is really encrypted: ".enc" files are os.urandom() bytes,
no key is generated, no network connection is made.

    python3 detector/simulate.py [--files 25] [--interval 0.2] [--keep]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter

from engine import DetectionEngine
from ransomwatch import Monitor

DEFAULT_FILE_COUNT = 25
DEFAULT_INTERVAL_S = 0.2
POLLS_BEFORE_ATTACK = 3
POLLS_AFTER_ATTACK = 5
FAKE_CIPHERTEXT_MIN_BYTES = 4096
PER_FILE_DELAY_S = 0.01
VICTIM_EXTENSIONS = (".txt", ".md", ".c", ".h", ".cpp", ".hpp")  # same as ProManager
PLAINTEXT_LINE = "Rapport de projet - ligne {n:04d} : donnees de test lisibles.\n"
PLAINTEXT_LINES = 40
NOTE_NAME = "RANÇON.txt"
NOTE_BODY = ("SIMULATION RansomWatch - aucun fichier reel n'a ete chiffre.\n"
             "Ce fichier imite le nom de la note de ProManager.\n")


class CollectingSink:
    """File-like sink that keeps the JSON lines it receives."""

    def __init__(self) -> None:
        self.lines = []

    def write(self, text: str) -> None:
        self.lines.extend(line for line in text.splitlines() if line)

    def flush(self) -> None:
        return None


def create_victim_files(project_dir: str, count: int) -> list:
    os.makedirs(project_dir, exist_ok=True)
    body = "".join(PLAINTEXT_LINE.format(n=i) for i in range(PLAINTEXT_LINES))
    paths = []
    for index in range(count):
        ext = VICTIM_EXTENSIONS[index % len(VICTIM_EXTENSIONS)]
        path = os.path.join(project_dir, f"fichier_{index:02d}{ext}")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        paths.append(path)
    return paths


def simulate_archive(archive_path: str, paths: list) -> None:
    """T1560.002-like step: archive the victim files (like libzip in ProManager)."""
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, os.path.basename(path))


def simulate_encryption(paths: list) -> None:
    """T1486-like step: write random bytes to X.enc, then delete X."""
    for path in paths:
        size = max(os.path.getsize(path), FAKE_CIPHERTEXT_MIN_BYTES)
        with open(path + ".enc", "wb") as handle:
            handle.write(os.urandom(size))
        os.remove(path)
        time.sleep(PER_FILE_DELAY_S)


def drop_note(project_dir: str) -> None:
    with open(os.path.join(project_dir, NOTE_NAME), "w", encoding="utf-8") as handle:
        handle.write(NOTE_BODY)


def run_simulation(workdir: str, file_count: int, interval_s: float,
                   echo: bool = True) -> list:
    """Run the scenario under ``workdir`` and return the alerts (dicts)."""
    tp_dir = os.path.join(workdir, "TP")
    project_dir = os.path.join(tp_dir, "Projet")
    paths = create_victim_files(project_dir, file_count)
    collector = CollectingSink()
    sinks = (sys.stdout, collector) if echo else (collector,)
    monitor = Monitor(tp_dir, DetectionEngine(), sinks)
    stop = threading.Event()
    thread = threading.Thread(target=monitor.run, args=(interval_s,),
                              kwargs={"stop": stop}, daemon=True)
    thread.start()
    try:
        time.sleep(interval_s * POLLS_BEFORE_ATTACK)
        simulate_archive(os.path.join(tp_dir, "Projet_temp.zip"), paths)
        simulate_encryption(paths)
        drop_note(project_dir)
        time.sleep(interval_s * POLLS_AFTER_ATTACK)
    finally:
        stop.set()
        thread.join()
    return [json.loads(line) for line in collector.lines]


def print_summary(alerts: list) -> None:
    counts = Counter(a["rule_id"] for a in alerts)
    print("\n=== RansomWatch simulation summary ===", file=sys.stderr)
    for rule_id in sorted(counts):
        print(f"  {rule_id}: {counts[rule_id]} alert(s)", file=sys.stderr)
    print(f"  total: {len(alerts)}", file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--files", type=int, default=DEFAULT_FILE_COUNT)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_S)
    parser.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = parser.parse_args(argv)
    if args.files <= 0 or args.interval <= 0:
        parser.error("--files and --interval must be > 0")
    workdir = tempfile.mkdtemp(prefix="ransomwatch-sim-")
    print(f"[simulate] sandbox: {workdir}", file=sys.stderr)
    try:
        alerts = run_simulation(workdir, args.files, args.interval)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
    print_summary(alerts)
    return 0 if alerts else 1


if __name__ == "__main__":
    sys.exit(main())
