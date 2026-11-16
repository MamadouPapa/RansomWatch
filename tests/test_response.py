import json
import os
import shutil
import tempfile
import unittest

import helpers
import response
from engine import DetectionEngine
from snapshot import CREATED, FileChange


class ResponseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rw-resp-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_contain_none_sends_nothing(self):
        suspect = response.SuspectProcess(os.getpid(), "self", "?", "/x")
        self.assertEqual(response.contain([suspect], response.CONTAIN_NONE), [])

    def test_evidence_found_through_fd_symlink(self):
        watched = os.path.realpath(os.path.join(self.tmp, "watched"))
        os.makedirs(watched)
        fd_dir = os.path.join(self.tmp, "proc", "4242", "fd")
        os.makedirs(fd_dir)
        os.symlink(os.path.join(watched, "doc.txt"), os.path.join(fd_dir, "3"))
        os.symlink("/", os.path.join(self.tmp, "proc", "4242", "cwd"))
        evidence = response._evidence_for(os.path.join(self.tmp, "proc", "4242"), watched)
        self.assertEqual(evidence, os.path.join(watched, "doc.txt"))

    def test_no_evidence_for_unrelated_process(self):
        proc = os.path.join(self.tmp, "proc", "7")
        os.makedirs(proc)
        os.symlink("/", os.path.join(proc, "cwd"))
        self.assertIsNone(response._evidence_for(proc, os.path.join(self.tmp, "w")))

    def test_pid_lookup_is_empty_without_proc(self):
        self.assertEqual(response.find_suspect_pids(self.tmp, proc_root="/no/proc"), ())

    def test_incident_file_is_json_lines(self):
        alert = DetectionEngine(wall_clock=helpers.FakeClock()).process(
            [FileChange(CREATED, "/w/RANSOM_NOTE.txt", 1)], 0.0)[0]
        path = os.path.join(self.tmp, "incident.jsonl")
        response.write_incident(path, alert.to_dict(), (), [])
        with open(path, encoding="utf-8") as handle:
            record = json.loads(handle.readline())
        self.assertEqual(record["alert"]["rule_id"], "RW-003")
        self.assertEqual(record["actions"], [])


if __name__ == "__main__":
    unittest.main()
