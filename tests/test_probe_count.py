"""Pins the probe count. The README says deleting a probe cannot quietly improve a score; this is what makes that true. If you add or remove
a probe on purpose, change EXPECTED here AND the number in README.md in the same commit."""
import unittest

from keycanary import loader

EXPECTED = 61


class ProbeCount(unittest.TestCase):
    def test_the_number_of_probes_is_pinned(self):
        self.assertEqual(len(loader.load()), EXPECTED, "the probe count changed: update EXPECTED and README.md together, on purpose")

    def test_probe_ids_are_unique(self):
        ids = [p.id for p in loader.load()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_readme_states_the_same_number(self):
        import os
        text = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"), encoding="utf-8").read()
        self.assertIn(f"{EXPECTED} ways", text)


if __name__ == "__main__":
    unittest.main()
