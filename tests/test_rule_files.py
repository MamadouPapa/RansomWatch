"""Stdlib-only structural checks of the detection-as-code files.

Full YAML parsing is done with PyYAML when it is installed (optional);
otherwise these checks still enforce the Sigma fields this project requires.
"""
import glob
import os
import re
import unittest

import helpers

SIGMA_DIR = os.path.join(helpers.PROJECT_ROOT, "rules", "sigma")
AUDITD_FILE = os.path.join(helpers.PROJECT_ROOT, "auditd", "ransomwatch.rules")
SURICATA_FILE = os.path.join(helpers.PROJECT_ROOT, "network", "ransomwatch.rules")
UUID_RE = re.compile(r"^id: [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.M)
COMMON_KEYS = ("title", "id", "status", "description", "references", "author",
               "date", "tags", "falsepositives", "level")
DETECTION_KEYS = ("logsource", "detection")
CORRELATION_KEYS = ("correlation",)

try:
    import yaml  # optional, never required by the project
except ImportError:
    yaml = None


def sigma_documents():
    for path in sorted(glob.glob(os.path.join(SIGMA_DIR, "*.yml"))):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for doc in re.split(r"^---$", text, flags=re.M):
            yield path, doc


class SigmaStructureTest(unittest.TestCase):
    def test_rules_exist(self):
        self.assertGreaterEqual(len(glob.glob(os.path.join(SIGMA_DIR, "*.yml"))), 4)

    def test_required_fields(self):
        ids = []
        for path, doc in sigma_documents():
            with self.subTest(file=os.path.basename(path), doc=doc[:40]):
                self.assertNotIn("\t", doc)
                is_correlation = re.search(r"^correlation:", doc, re.M) is not None
                keys = COMMON_KEYS + (CORRELATION_KEYS if is_correlation else DETECTION_KEYS)
                for key in keys:
                    self.assertRegex(doc, rf"(?m)^{key}:")
                self.assertRegex(doc, UUID_RE)
                self.assertRegex(doc, r"(?m)^status: experimental$")
                self.assertRegex(doc, r"(?m)^author: Papa Mamadou Gueye$")
                self.assertRegex(doc, r"(?m)^date: 2026/11/16$")
                self.assertRegex(doc, r"(?m)^    - attack\.t\d{4}(\.\d{3})?$")
                if not is_correlation:
                    self.assertRegex(doc, r"(?m)^    condition: ")
                ids.append(UUID_RE.search(doc).group(0))
        self.assertEqual(len(ids), len(set(ids)), "duplicate Sigma ids")

    @unittest.skipIf(yaml is None, "PyYAML not installed: structural checks only")
    def test_yaml_parses(self):
        for path in glob.glob(os.path.join(SIGMA_DIR, "*.yml")):
            with open(path, encoding="utf-8") as handle:
                docs = list(yaml.safe_load_all(handle))
            self.assertTrue(all(isinstance(d, dict) for d in docs), path)


class AuditdRulesTest(unittest.TestCase):
    def test_every_rule_line_is_an_auditctl_option(self):
        with open(AUDITD_FILE, encoding="utf-8") as handle:
            lines = [l.strip() for l in handle if l.strip() and not l.startswith("#")]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, r"^-(w|a|b|e|f) ")
        self.assertTrue(any("-S connect" in l and "-k net_connect" in l for l in lines))
        self.assertFalse(any(l.startswith("-D") for l in lines), "must not flush rules")


class SuricataRulesTest(unittest.TestCase):
    def test_rules_are_well_formed_with_unique_sids(self):
        with open(SURICATA_FILE, encoding="utf-8") as handle:
            rules = [l.strip() for l in handle if l.strip() and not l.startswith("#")]
        sids = []
        for rule in rules:
            with self.subTest(rule=rule[:60]):
                self.assertRegex(rule, r"^alert tcp .+ \(.*msg:\".+\";.*sid:\d+; rev:\d+;\)$")
                self.assertIn("4242", rule)
                sids.append(re.search(r"sid:(\d+);", rule).group(1))
        self.assertEqual(len(sids), len(set(sids)))
        self.assertTrue(any("dsize:48" in r for r in rules))


if __name__ == "__main__":
    unittest.main()
