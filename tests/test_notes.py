import unicodedata
import unittest

import helpers  # noqa: F401
from notes import fold_name, match_ransom_note


class RansomNoteMatchingTest(unittest.TestCase):
    def test_promanager_note_nfc(self):
        self.assertEqual(match_ransom_note("RANÇON.txt"), "rancon")

    def test_promanager_note_nfd(self):
        nfd = unicodedata.normalize("NFD", "RANÇON.txt")
        self.assertEqual(match_ransom_note(nfd), "rancon")

    def test_common_note_names(self):
        for name in ("HOW_TO_DECRYPT.txt", "ransom_note.html", "README_FOR_DECRYPT.txt",
                     "!!!README!!!.txt", "_readme.txt", "RESTORE_MY_FILES.txt",
                     "YOUR_FILES_ARE_ENCRYPTED.txt", "help-to-recover.html"):
            with self.subTest(name=name):
                self.assertIsNotNone(match_ransom_note(name))

    def test_benign_names_do_not_match(self):
        for name in ("README.md", "readme.txt", "rapport.txt", "main.c",
                     "Projet_temp.zip", "notes.md.enc"):
            with self.subTest(name=name):
                self.assertIsNone(match_ransom_note(name))

    def test_fold_strips_accents(self):
        self.assertEqual(fold_name("rançon"), "RANCON")


if __name__ == "__main__":
    unittest.main()
