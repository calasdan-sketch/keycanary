"""n/a propagation, NOT SCORED exit, cost-control split, and README-vs-real-run."""
import io
import os
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from keycanary import harness, loader, profiles, report
from keycanary.__main__ import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class NotApplicable(unittest.TestCase):
    def test_probe_that_cannot_run_on_baseline_is_na_for_every_profile(self):
        # a Read of .env that claude-env-deny would block, but whose command cannot run here
        probe = loader.Probe(id="x", category="direct read", attack="x",
                             tool={"tool_name": "Read", "tool_input": {"file_path": "/p/.env"}},
                             run={"kind": "none"})
        for name in ("none", "claude-env-deny"):
            self.assertEqual(harness.run(name, [probe])[0].status, "n/a", name)


class NotScored(unittest.TestCase):
    def test_unavailable_profile_prints_not_scored_no_scoreline_and_exits_nonzero(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(profiles, "get", side_effect=ImportError("x")), \
                redirect_stdout(out), redirect_stderr(err):
            rc = main(["--profile", "stuntkey-hook"])
        self.assertNotEqual(rc, 0)
        self.assertIn("NOT SCORED", err.getvalue())
        self.assertNotIn("LEAK SCORE", out.getvalue())


class CostControlSplit(unittest.TestCase):
    def test_spend_probes_are_not_in_the_headline(self):
        results = harness.run("none")
        leak, cost = report.split(results)
        self.assertEqual({r.probe_id for r in cost}, {"runaway-loop-no-cap", "unbounded-retry"})
        self.assertEqual(sum(report.summary(leak).values()), len(results) - 2)
        self.assertIn("COST CONTROL", report.to_table(results, "none"))


class ReadmeMatchesRealRun(unittest.TestCase):
    """Deterministic rows (no scanner, no stuntkey) must equal what a run prints."""

    def test_none_and_env_deny_rows(self):
        text = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        for name in ("none", "claude-env-deny"):
            row = re.search(rf"^\| `{name}` \|.*?\| (\d+) \| (\d+) \| [^|]*\|\s*$", text, re.M)
            self.assertIsNotNone(row, name)
            for canary, claimed in (("prefixed", row.group(1)), ("opaque", row.group(2))):
                with mock.patch.dict(os.environ, {"KEYCANARY_CANARY": canary}):
                    got = report.summary(report.split(harness.run(name))[0])["leaked"]
                self.assertEqual(str(got), claimed, f"{name}/{canary}: README is stale")


if __name__ == "__main__":
    unittest.main()
