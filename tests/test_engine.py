"""Rule-level tests with a fake clock and a fake entropy reader (no I/O)."""
import unittest

import helpers
from engine import DetectionEngine, DetectorConfig
from snapshot import CREATED, DELETED, MODIFIED, FileChange, FileState

PLAIN, CIPHER = 4.5, 7.95
SIZE = 4096


def engine_with(entropies=None, **cfg):
    table = dict(entropies or {})
    return DetectionEngine(DetectorConfig(**cfg), entropy_reader=table.get,
                           wall_clock=helpers.FakeClock())


def rule_ids(alerts):
    return [a.rule_id for a in alerts]


class BurstRuleTest(unittest.TestCase):
    def test_burst_above_threshold_alerts_once(self):
        engine = engine_with(burst_threshold=5, burst_window_s=10.0)
        changes = [FileChange(CREATED, f"/w/f{i}.txt", 10) for i in range(8)]
        alerts = engine.process(changes, now=1.0)
        self.assertEqual(rule_ids(alerts).count("RW-001"), 1)
        burst = [a for a in alerts if a.rule_id == "RW-001"][0]
        self.assertEqual(burst.details["events_in_window"], 5)
        self.assertEqual(burst.mitre_technique, "T1486")

    def test_slow_changes_below_threshold_do_not_alert(self):
        engine = engine_with(burst_threshold=5, burst_window_s=10.0)
        alerts = []
        for i in range(10):  # one change every 3 s -> at most 4 per window
            alerts += engine.process([FileChange(MODIFIED, "/w/a.txt", 10)], now=i * 3.0)
        self.assertNotIn("RW-001", rule_ids(alerts))

    def test_burst_rearms_after_cooldown(self):
        engine = engine_with(burst_threshold=3, burst_window_s=5.0)
        batch = [FileChange(CREATED, f"/w/f{i}", 10) for i in range(3)]
        first = engine.process(batch, now=0.0)
        second = engine.process(batch, now=20.0)
        self.assertEqual(rule_ids(first + second).count("RW-001"), 2)


class EntropyRuleTest(unittest.TestCase):
    def test_new_high_entropy_file_alerts(self):
        engine = engine_with({"/w/a.txt.enc": CIPHER})
        alerts = engine.process([FileChange(CREATED, "/w/a.txt.enc", SIZE)], 0.0)
        self.assertEqual(rule_ids(alerts), ["RW-002"])

    def test_baseline_of_replaced_original_is_reported(self):
        engine = engine_with({"/w/a.txt": PLAIN, "/w/a.txt.enc": CIPHER})
        engine.seed({"/w/a.txt": FileState(SIZE, 1, 1)})
        alert = engine.process([FileChange(CREATED, "/w/a.txt.enc", SIZE)], 0.0)[0]
        self.assertEqual(alert.details["baseline_bits_per_byte"], PLAIN)

    def test_already_high_entropy_file_does_not_alert(self):
        engine = engine_with({"/w/blob.bin": CIPHER})
        engine.seed({"/w/blob.bin": FileState(SIZE, 1, 1)})
        alerts = engine.process([FileChange(MODIFIED, "/w/blob.bin", SIZE)], 0.0)
        self.assertEqual(alerts, ())

    def test_compressed_formats_and_small_files_are_ignored(self):
        engine = engine_with({"/w/x.zip": CIPHER, "/w/tiny.txt": CIPHER})
        alerts = engine.process([FileChange(CREATED, "/w/x.zip", SIZE),
                                 FileChange(CREATED, "/w/tiny.txt", 10)], 0.0)
        self.assertEqual(alerts, ())

    def test_plain_text_does_not_alert(self):
        engine = engine_with({"/w/a.txt": PLAIN})
        self.assertEqual(engine.process([FileChange(CREATED, "/w/a.txt", SIZE)], 0.0), ())


class RansomNoteRuleTest(unittest.TestCase):
    def test_note_creation_is_critical(self):
        alert = engine_with().process([FileChange(CREATED, "/w/RANÇON.txt", 10)], 0.0)[0]
        self.assertEqual((alert.rule_id, alert.severity), ("RW-003", "critical"))


class ArchiveThenDeleteRuleTest(unittest.TestCase):
    def _attack(self, engine, deletions, delete_time):
        changes = [FileChange(CREATED, "/w/TP/Projet_temp.zip", SIZE)]
        engine.process(changes, now=0.0)
        dels = [FileChange(DELETED, f"/w/TP/Projet/f{i}.txt", 10) for i in range(deletions)]
        return engine.process(dels, now=delete_time)

    def test_archive_then_deletions_alerts(self):
        alerts = self._attack(engine_with(archive_delete_threshold=3), 5, 1.0)
        self.assertEqual(rule_ids(alerts), ["RW-004"])
        self.assertEqual(alerts[0].mitre_technique, "T1560.002")

    def test_deletions_outside_window_are_ignored(self):
        engine = engine_with(archive_delete_threshold=3, archive_window_s=10.0)
        self.assertEqual(self._attack(engine, 5, 60.0), ())

    def test_deletions_without_archive_are_ignored(self):
        dels = [FileChange(DELETED, f"/w/f{i}.txt", 10) for i in range(10)]
        self.assertEqual(engine_with().process(dels, 0.0), ())


class ExtensionSwapRuleTest(unittest.TestCase):
    def test_encrypt_and_remove_pattern_alerts(self):
        engine = engine_with(swap_threshold=3)
        changes = []
        for i in range(4):
            changes += [FileChange(CREATED, f"/w/f{i}.c.enc", 10),
                        FileChange(DELETED, f"/w/f{i}.c", 10)]
        alerts = engine.process(sorted(changes, key=lambda c: c.kind != CREATED), 0.0)
        swap = [a for a in alerts if a.rule_id == "RW-005"]
        self.assertEqual(len(swap), 1)
        self.assertEqual(swap[0].details["new_extensions"], [".enc"])

    def test_unrelated_create_and_delete_do_not_alert(self):
        engine = engine_with(swap_threshold=1)
        alerts = engine.process([FileChange(CREATED, "/w/new.txt", 10),
                                 FileChange(DELETED, "/w/old.txt", 10)], 0.0)
        self.assertNotIn("RW-005", rule_ids(alerts))


class ConfigValidationTest(unittest.TestCase):
    def test_invalid_thresholds_are_rejected(self):
        for bad in ({"burst_threshold": 0}, {"entropy_threshold": 9.0},
                    {"swap_window_s": -1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                DetectorConfig(**bad)

    def test_alert_serialises_with_mitre_block(self):
        alert = engine_with().process([FileChange(CREATED, "/w/RANSOM.txt", 1)], 0.0)[0]
        data = alert.to_dict()
        self.assertEqual(set(data), {"timestamp", "rule_id", "rule_name", "severity",
                                     "mitre", "details"})
        self.assertEqual(data["mitre"]["technique_id"], "T1486")


if __name__ == "__main__":
    unittest.main()
