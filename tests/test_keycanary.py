"""Tests for keycanary. Standard library only (run with ``python -m unittest`` or pytest).

No test file contains a contiguous secret-looking literal: canaries and
encodings are built at runtime."""

from __future__ import annotations

import base64
import codecs
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from keycanary import detect, harness, loader, profiles, report, sandbox  # noqa: E402
from keycanary.runner import Result  # noqa: E402

CANARY = "sk-" + "canary" + "-" + "0123456789abcdef"
NAIVE = f'exec:{sys.executable} {os.path.join(ROOT, "examples", "naive_hook.py")}'


def run_cli(*args: str) -> tuple[int, str, str]:
    proc = subprocess.run([sys.executable, "-m", "keycanary", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    return proc.returncode, proc.stdout, proc.stderr


class PinnedSet(unittest.TestCase):
    def test_counts_are_pinned(self):
        probes = loader.load()
        for suite, want in loader.EXPECTED.items():
            self.assertEqual(sum(p.suite == suite for p in probes), want, suite)
        self.assertEqual(loader.EXPECTED["core"], 61)

    def test_deleting_a_probe_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            for name in os.listdir(loader.PROBE_DIR):
                with open(os.path.join(loader.PROBE_DIR, name), encoding="utf-8") as f:
                    data = json.load(f)
                if name == "spend.json":
                    data = data[:1]
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    json.dump(data, f)
            with self.assertRaises(loader.ProbeSetError):
                loader.load(d, enforce_pin=True)

    def test_hash_changes_when_a_probe_changes(self):
        probes = loader.load()
        h = loader.probe_set_hash(probes)
        self.assertEqual(h, loader.probe_set_hash(list(reversed(probes))))
        from dataclasses import replace
        changed = [replace(probes[0], attack="different")] + probes[1:]
        self.assertEqual(h, loader.probe_set_hash(changed))  # attack text is prose
        changed = [replace(probes[0], run={"kind": "sh", "cmd": "true"})] + probes[1:]
        self.assertNotEqual(h, loader.probe_set_hash(changed))

    def test_event_shape_matches_what_an_agent_emits(self):
        for p in loader.load():
            if p.check not in ("write_tamper", "control"):
                self.assertNotEqual(p.tool["tool_name"], "Write", p.id)
            for pre in p.pre:
                self.assertEqual(pre["tool_name"], "Write", p.id)

    def test_controls_have_expectations(self):
        for p in loader.load():
            if p.suite == "control" and p.run.get("kind") != "none":
                self.assertTrue(p.expect, p.id)


class Detect(unittest.TestCase):
    def test_encodings_found_at_every_alignment(self):
        for pre in ("", "x", "xy", "API_KEY="):
            for post in ("", "\n", "zz"):
                enc = base64.b64encode((pre + CANARY + post).encode()).decode()
                wrapped = "\n".join(enc[i:i + 76] for i in range(0, len(enc), 76))
                self.assertEqual(detect.find_leak(wrapped, CANARY), "base64", (pre, post))

    def test_other_forms(self):
        self.assertEqual(detect.find_leak(CANARY[::-1], CANARY), "reversed")
        self.assertEqual(detect.find_leak(codecs.encode(CANARY, "rot_13"), CANARY), "rot13")
        spaced_hex = " ".join(f"{b:02x}" for b in CANARY.encode())
        self.assertEqual(detect.find_leak(spaced_hex, CANARY), "hex")
        self.assertEqual(detect.find_leak(" ".join(CANARY), CANARY), "split by whitespace")
        self.assertEqual(detect.find_leak("prefix " + CANARY, CANARY), "plain")

    def test_clean_output_and_empty_secret(self):
        self.assertIsNone(detect.find_leak("hello world", CANARY))
        self.assertIsNone(detect.find_leak("anything", ""))
        self.assertIsNone(detect.find_leak("", CANARY))


class Sandbox(unittest.TestCase):
    def test_host_environment_is_not_inherited(self):
        name = "KEYCANARY_TEST_HOST_" + "TOK"
        os.environ[name] = "host-value"
        try:
            sbx = sandbox.build()
            try:
                self.assertNotIn(name, sbx.env)
                self.assertEqual(sbx.env["API_KEY"], sbx.canary)
                self.assertEqual(sbx.env["HOME"], sbx.home)
            finally:
                sandbox.destroy(sbx)
        finally:
            del os.environ[name]

    def test_canaries_are_unique_per_run(self):
        self.assertNotEqual(sandbox.new_canary(), sandbox.new_canary())


class Scoring(unittest.TestCase):
    def test_none_leaks_and_is_rankable(self):
        results = harness.run("none")
        s, m = report.summary(results), report.metrics(results)
        self.assertEqual(s["blocked"] + s["masked"], 0)
        self.assertGreater(s["leaked"], 40)
        self.assertTrue(m["rankable"])
        self.assertEqual(report.control_summary(results)["ok"], 10)

    def test_deny_all_cannot_win(self):
        results = harness.run("deny-all")
        self.assertEqual(report.summary(results)["leaked"], 0)
        self.assertEqual(report.control_summary(results)["overblocked"], 10)
        self.assertFalse(report.metrics(results)["rankable"])
        self.assertIn("NOT RANKABLE", report.to_table(results, "deny-all"))

    def test_mask_all_cannot_win(self):
        results = harness.run("mask-all")
        self.assertGreaterEqual(report.control_summary(results)["altered"], 8)
        self.assertFalse(report.metrics(results)["rankable"])

    def test_masked_requires_canary_in_raw_output(self):
        # a command that never printed the canary is n/a under any profile
        probe = loader.Probe(id="t", category="t", attack="t",
                             tool={"tool_name": "Bash", "tool_input": {"command": "true"}},
                             run={"kind": "sh", "cmd": "echo nothing"})
        out = harness.run("mask-all", [probe])
        self.assertEqual(out[0].status, "n/a")

    def test_encoded_leak_is_caught(self):
        probe = [p for p in loader.load() if p.id == "b64-env-output"]
        self.assertEqual(harness.run("none", probe)[0].status, "leaked")

    def test_two_event_probe_blocks_on_the_write(self):
        probe = [p for p in loader.load() if p.id == "script-prints-environ"]
        self.assertTrue(probe[0].pre)
        seen = []

        def spy(payload):
            seen.append(payload["tool_name"])
            return payload["tool_name"] == "Write", "no scripts"
        sbx = sandbox.build()
        try:
            from keycanary.runner import run_probe
            res = run_probe(probe[0], sbx, spy, "spy")
        finally:
            sandbox.destroy(sbx)
        self.assertEqual(res.status, "blocked")
        self.assertEqual(seen, ["Write"])


class ExecProfile(unittest.TestCase):
    def test_naive_hook_scores_and_leaves_gaps(self):
        results = harness.run(NAIVE)
        s = report.summary(results)
        self.assertGreater(s["blocked"], 10)
        self.assertGreater(s["leaked"], 5)           # naive on purpose
        # the regex also hits the harmless .env.example: the controls catch it
        broken = {r.probe_id for r in results if r.status == "overblocked"}
        self.assertIn("ctl-read-env-example", broken)
        self.assertFalse(report.metrics(results)["rankable"])

    def test_missing_command_aborts(self):
        with self.assertRaises(profiles.ProfileError):
            harness.run("exec:/no/such/hook-binary")

    def test_unparseable_and_failing_hooks_abort(self):
        bad_json = f'exec:{sys.executable} -c "print(1+1, \'x\')"'
        with self.assertRaises(profiles.ProfileError):
            harness.run(bad_json)
        crash = f'exec:{sys.executable} -c "import sys; sys.exit(7)"'
        with self.assertRaises(profiles.ProfileError):
            harness.run(crash)

    def test_empty_exec_is_rejected(self):
        with self.assertRaises(profiles.ProfileError):
            profiles.get("exec:")

    def test_exit_2_blocks(self):
        hook = f'exec:{sys.executable} -c "import sys; sys.stderr.write(\'nope\'); sys.exit(2)"'
        results = harness.run(hook)
        self.assertEqual(report.summary(results)["leaked"], 0)
        self.assertEqual(report.control_summary(results)["overblocked"], 10)

    def test_hook_receives_canary_and_sandbox_home(self):
        code = ("import os,sys,json;json.load(sys.stdin);"
                "sys.exit(0 if os.environ.get('KEYCANARY_CANARY','').startswith('sk-') "
                "and os.environ.get('HOME')==os.environ.get('KEYCANARY_SANDBOX') else 9)")
        harness.run(f'exec:{sys.executable} -c "{code}"')  # raises ProfileError on exit 9


class Report(unittest.TestCase):
    def test_clean_strips_control_and_bidi(self):
        nasty = "ok\x1b[31mred\u202eevil\u200b\nnext\x07"
        out = report.clean(nasty)
        for ch in ("\x1b", "\u202e", "\u200b", "\n", "\x07"):
            self.assertNotIn(ch, out)
        self.assertIn("okred", out.replace("[31m", "").replace("?", ""))

    def test_hostile_reason_never_reaches_any_format(self):
        r = [Result("p1", "cat\x1b[2J", "x", "leaked", "boom\u202e\x1b]0;t\x07", "core")]
        for fmt in report.FORMATS:
            text = report.render(fmt, r, "prof\x1b")
            self.assertNotIn("\x1b", text, fmt)
            self.assertNotIn("\u202e", text, fmt)

    def test_junit_and_sarif_parse(self):
        import xml.etree.ElementTree as ET
        results = [Result("a", "c", "x", "leaked", "d", "core"),
                   Result("b", "c", "x", "n/a", "d", "core"),
                   Result("c", "c", "x", "blocked", "d", "core")]
        root = ET.fromstring(report.to_junit(results, "x"))
        self.assertEqual((root.get("tests"), root.get("failures"), root.get("skipped")), ("3", "1", "1"))
        sarif = json.loads(report.to_sarif(results, "x"))
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_json_has_metadata(self):
        data = json.loads(report.to_json(harness.run("none", loader.load()[:3]), "none",
                                         probe_hash="abc"))
        self.assertEqual(data["meta"]["probe_set_sha256"], "abc")
        self.assertIn("metrics", data)


class Cli(unittest.TestCase):
    def test_gate_exit_codes(self):
        code, _, _ = run_cli("--profile", "none", "--suite", "core", "--format", "json")
        self.assertEqual(code, 0)
        code, _, err = run_cli("--profile", "none", "--suite", "core", "--fail-on-leak")
        self.assertEqual(code, 1)
        self.assertIn("GATE FAILED", err)
        code, _, _ = run_cli("--profile", "deny-all", "--fail-on-leak")
        self.assertEqual(code, 0)
        code, _, err = run_cli("--profile", "deny-all", "--strict")
        self.assertEqual(code, 1)
        self.assertIn("benign controls", err)

    def test_bad_profile_and_bad_args_exit_2(self):
        self.assertEqual(run_cli("--profile", "nope")[0], 2)
        self.assertEqual(run_cli("--profile", "exec:/no/such/x")[0], 2)
        self.assertEqual(run_cli("--repeat", "0")[0], 2)

    def test_baseline_regression(self):
        code, out, _ = run_cli("--profile", "deny-all", "--suite", "core", "--json")
        self.assertEqual(code, 0)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "base.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(out)
            self.assertEqual(run_cli("--profile", "deny-all", "--suite", "core",
                                     "--baseline", path)[0], 0)
            code, _, err = run_cli("--profile", "none", "--suite", "core", "--baseline", path)
            self.assertEqual(code, 1)
            self.assertIn("new leaks", err)
            data = json.loads(out)
            data["meta"]["probe_set_sha256"] = "different"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            self.assertEqual(run_cli("--profile", "none", "--baseline", path)[0], 2)

    def test_list_and_repeat(self):
        code, out, _ = run_cli("--list")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), sum(loader.EXPECTED.values()))
        code, out, _ = run_cli("--profile", "none", "--suite", "encoded", "--repeat", "2",
                               "--strict", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["unstable"], [])


if __name__ == "__main__":
    unittest.main()
