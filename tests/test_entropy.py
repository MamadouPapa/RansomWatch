import os
import tempfile
import unittest

import helpers  # noqa: F401
from entropy import file_entropy, shannon_entropy

RANDOM_SAMPLE_BYTES = 16384
ENCRYPTED_LOOKING_MIN = 7.9


class ShannonEntropyTest(unittest.TestCase):
    def test_empty_input_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_single_repeated_byte_is_zero(self):
        self.assertEqual(shannon_entropy(b"A" * 1000), 0.0)

    def test_two_equiprobable_symbols_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy(b"AB" * 500), 1.0)

    def test_all_byte_values_once_is_eight_bits(self):
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0)

    def test_random_bytes_look_encrypted(self):
        self.assertGreater(shannon_entropy(os.urandom(RANDOM_SAMPLE_BYTES)),
                           ENCRYPTED_LOOKING_MIN)

    def test_plain_text_is_well_below_threshold(self):
        text = ("Rapport de projet : donnees lisibles et repetitives. " * 80).encode()
        self.assertLess(shannon_entropy(text), 5.0)


class FileEntropyTest(unittest.TestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(file_entropy("/nonexistent/ransomwatch/file"))

    def test_reads_only_sample(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"A" * 100 + os.urandom(RANDOM_SAMPLE_BYTES))
        try:
            self.assertEqual(file_entropy(handle.name, max_bytes=100), 0.0)
        finally:
            os.remove(handle.name)


if __name__ == "__main__":
    unittest.main()
