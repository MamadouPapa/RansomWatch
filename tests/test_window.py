import unittest

import helpers  # noqa: F401
from window import SlidingWindow


class SlidingWindowTest(unittest.TestCase):
    def test_counts_events_inside_window(self):
        window = SlidingWindow(10.0)
        for t in (0.0, 1.0, 2.0):
            window.add(t)
        self.assertEqual(window.count(5.0), 3)

    def test_old_events_expire(self):
        window = SlidingWindow(10.0)
        window.add(0.0)
        window.add(5.0)
        self.assertEqual(window.count(10.0), 1)   # event at t=0 is now out
        self.assertEqual(window.count(15.0), 0)

    def test_add_returns_current_count(self):
        window = SlidingWindow(2.0)
        self.assertEqual(window.add(0.0), 1)
        self.assertEqual(window.add(1.0), 2)
        self.assertEqual(window.add(3.5), 1)

    def test_payloads_follow_expiry(self):
        window = SlidingWindow(5.0)
        window.add(0.0, "a")
        window.add(4.0, "b")
        self.assertEqual(window.payloads(6.0), ("b",))

    def test_rejects_non_positive_length(self):
        with self.assertRaises(ValueError):
            SlidingWindow(0)


if __name__ == "__main__":
    unittest.main()
