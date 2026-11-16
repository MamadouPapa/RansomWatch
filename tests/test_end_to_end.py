"""End-to-end: real files in a temp dir, random bytes as fake ciphertext.

The real ransomware is never compiled nor executed here.
"""
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile

import helpers  # noqa: F401
from engine import DetectionEngine, DetectorConfig
from ransomwatch import Monitor, main
from simulate import run_simulation

VICTIMS = 12
PLAIN_BODY = ("ligne de texte lisible pour le test de bout en bout\n" * 60)
FAKE_CIPHER_BYTES = 4096
EXPECTED_RULES = {"RW-001", "RW-002", "RW-003", "RW-004", "RW-005"}


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="rw-test-")
        self.project = os.path.join(self.workdir, "Projet")
        os.makedirs(self.project)
        self.victims = []
        for i in range(VICTIMS):
            path = os.path.join(self.project, f"doc_{i}.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(PLAIN_BODY)
            self.victims.append(path)

    def tearDown(self):
        shutil.rmtree(self.workdir, ignore_errors=True)

    def _monitor(self, sink):
        cfg = DetectorConfig(burst_threshold=10)
        return Monitor(self.workdir, DetectionEngine(cfg), (sink,))

    def test_simulated_attack_triggers_every_rule(self):
        sink = io.StringIO()
        monitor = self._monitor(sink)
        self.assertEqual(monitor.step(), ())  # quiet baseline
        with zipfile.ZipFile(os.path.join(self.workdir, "Projet_temp.zip"), "w") as z:
            for path in self.victims:
                z.write(path, os.path.basename(path))
        for path in self.victims:
            with open(path + ".enc", "wb") as handle:
                handle.write(os.urandom(FAKE_CIPHER_BYTES))
            os.remove(path)
        with open(os.path.join(self.project, "RANÇON.txt"), "w", encoding="utf-8") as h:
            h.write("simulation\n")
        alerts = monitor.step()
        self.assertEqual({a.rule_id for a in alerts}, EXPECTED_RULES)
        lines = [json.loads(l) for l in sink.getvalue().splitlines()]
        self.assertEqual(len(lines), len(alerts))
        self.assertTrue(all("mitre" in line for line in lines))

    def test_benign_editing_stays_quiet(self):
        monitor = self._monitor(io.StringIO())
        for path in self.victims[:3]:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("une modification normale\n")
        self.assertEqual(monitor.step(), ())

    def test_simulation_script_produces_alerts(self):
        alerts = run_simulation(self.workdir, file_count=8, interval_s=0.05, echo=False)
        rules = {a["rule_id"] for a in alerts}
        self.assertTrue({"RW-002", "RW-003", "RW-004", "RW-005"} <= rules)


class CliTest(unittest.TestCase):
    def test_kill_requires_respond(self):
        with self.assertRaises(SystemExit):
            main([tempfile.gettempdir(), "--kill", "--duration", "0"])

    def test_missing_directory_is_rejected(self):
        with self.assertRaises(SystemExit):
            main(["/nonexistent/ransomwatch/dir"])


if __name__ == "__main__":
    unittest.main()
