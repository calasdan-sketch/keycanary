"""Round 3 tests: wider judge, hardened exec adapter, process handling, CLI.

No contiguous secret-looking literal appears here: canaries and encodings are
built at runtime."""

from __future__ import annotations

import base64
import gzip
import html
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import zlib
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from keycanary import _proc, detect, harness, loader, profiles, report, sandbox  # noqa: E402

CANARY = "sk-" + "canary" + "-" + "0123456789abcdef"


def run_cli(*args: str) -> tuple[int, str, str]:
    proc = subprocess.run([sys.executable, "-m", "keycanary", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    return proc.returncode, proc.stdout, proc.stderr


def hook(code: str) -> str:
    return f"exec:{sys.executable} -c \"{code}\""


class WiderJudge(unittest.TestCase):
    def _forms(self):
        raw = CANARY.encode()
        b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
        return {
            "different letter case": CANARY.upper(),
            "split by punctuation": ".".join(CANARY),
            "base64": base64.urlsafe_b64encode(b"?>>" + raw).decode(),
            "base32": base64.b32encode(b"ab" + raw).decode(),
            "hex": ":".join(f"{b:02x}" for b in raw),
            "base64+gzip": b64(gzip.compress(raw)),
            "base64 > base64": b64(b64(raw).encode()),
            "hex+gzip": zlib.compress(raw).hex(),
            "percent": "".join(f"%{b:02x}" for b in raw),
            "backslash": "".join(f"\\u{ord(c):04x}" for c in CANARY),
            "entities": "".join(f"&#{ord(c)};" for c in CANARY),
            "codes": " ".join(str(b) for b in raw),
        }

    def test_each_extra_form_is_found(self):
        for name, text in self._forms().items():
            self.assertIsNotNone(detect.find_leak("out: " + text + " end", CANARY), name)

    def test_triple_nesting_found_but_not_beyond(self):
        b = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
        self.assertIsNotNone(detect.find_leak(b(b(b(CANARY))), CANARY))
        self.assertIsNone(detect.find_leak(b(b(b(b(b(CANARY))))), CANARY))

    def test_no_false_positives_on_ordinary_output(self):
        text = ("INFO listening on :8080\nBearer " + "a" * 40 + "\n"
                + base64.b64encode(b"hello world, nothing to see here").decode()
                + "\n" + "fedcba9876543210" * 4 + "\nsk-live-notthecanary-0123\n")
        self.assertIsNone(detect.find_leak(text, CANARY))

    def test_zip_bomb_is_bounded(self):
        bomb = base64.b64encode(zlib.compress(b"A" * 300_000_000)).decode()
        t = time.time()
        self.assertIsNone(detect.find_leak(bomb, CANARY))
        self.assertLess(time.time() - t, 20)

    def test_huge_input_is_bounded(self):
        t = time.time()
        self.assertIsNone(detect.find_leak("x" * 1_900_000 + " 12 34" * 1000, CANARY))
        self.assertLess(time.time() - t, 20)


class ProcessHandling(unittest.TestCase):
    def test_background_grandchild_cannot_hang_the_run(self):
        if os.name == "nt":
            self.skipTest("POSIX process groups")
        t = time.time()
        done = _proc.run(["bash", "-c", "sleep 30 & sleep 30"], timeout=1)
        self.assertTrue(done.timed_out)
        self.assertLess(time.time() - t, 8)

    def test_endless_output_is_capped(self):
        if os.name == "nt":
            self.skipTest("needs yes(1)")
        done = _proc.run(["yes"], timeout=1, cap=1000)
        self.assertEqual(len(done.stdout), 1000)
        self.assertTrue(done.truncated)

    def test_exec_hook_printing_forever_aborts(self):
        code = "import sys\nwhile True: sys.stdout.write('x'*65536)"
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
        try:
            with mock.patch.object(profiles, "EXEC_MAX_OUTPUT", 100_000):
                with self.assertRaises(profiles.ProfileError):
                    harness.run(f"exec:{sys.executable} {f.name}", probes=loader.load()[:1])
        finally:
            os.unlink(f.name)

    def test_exec_hook_that_sleeps_aborts_fast(self):
        with mock.patch.object(profiles, "EXEC_TIMEOUT", 1):
            t = time.time()
            with self.assertRaises(profiles.ProfileError):
                harness.run(hook("import time; time.sleep(30)"), probes=loader.load()[:1])
            self.assertLess(time.time() - t, 10)

    def test_two_runs_at_once_leave_nothing_behind(self):
        before = {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("keycanary-")}
        probes = [p for p in loader.load() if p.id in ("read-env", "env-dump")]
        out = []
        ts = [threading.Thread(target=lambda: out.append(harness.run("none", probes)))
              for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        after = {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("keycanary-")}
        self.assertEqual(after - before, set())
        self.assertEqual(len(out), 4)

    def test_aborted_run_still_deletes_its_sandbox(self):
        before = {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("keycanary-")}
        with self.assertRaises(profiles.ProfileError):
            harness.run(hook("import sys; sys.exit(9)"), probes=loader.load()[:1])
        after = {d for d in os.listdir(tempfile.gettempdir()) if d.startswith("keycanary-")}
        self.assertEqual(after - before, set())

    def test_sandbox_path_with_spaces_and_unicode(self):
        with tempfile.TemporaryDirectory(prefix="kc \u00e9 ") as d:
            with mock.patch.dict(os.environ, {"TMPDIR": d, "TMP": d, "TEMP": d}):
                with mock.patch.object(tempfile, "tempdir", None):
                    probes = [p for p in loader.load()
                              if p.id in ("read-env", "glob-wildcard-env", "symlink-read-env",
                                          "tar-pipe-env", "ctl-cat-environment-docs")]
                    results = harness.run("none", probes)
        for r in results:
            self.assertIn(r.status, ("leaked", "ok"), (r.probe_id, r.detail))


class ExecProtocol(unittest.TestCase):
    PROBES = ["read-env", "ctl-echo"]

    def _run(self, code: str):
        probes = [p for p in loader.load() if p.id in self.PROBES]
        return {r.probe_id: r for r in harness.run(hook(code), probes)}

    def test_deprecated_top_level_block_counts_as_deny(self):
        res = self._run("import json;print(json.dumps({'decision':'block','reason':'no'}))")
        self.assertEqual(res["read-env"].status, "blocked")

    def test_ask_is_not_counted_as_a_block_and_says_so(self):
        res = self._run("import json;print(json.dumps({'hookSpecificOutput':"
                        "{'permissionDecision':'ask','permissionDecisionReason':'sure?'}}))")
        self.assertEqual(res["read-env"].status, "leaked")
        self.assertIn("asked the user", res["read-env"].detail)
        self.assertEqual(res["ctl-echo"].status, "ok")

    def test_hook_gets_the_common_fields(self):
        code = ("import sys,json,os;e=json.load(sys.stdin);"
                "need=('session_id','cwd','permission_mode','transcript_path','tool_use_id');"
                "sys.exit(0 if all(k in e for k in need) and e['cwd']==os.environ['CLAUDE_PROJECT_DIR']"
                " and e['tool_use_id'].startswith('toolu_') else 9)")
        self._run(code)  # raises ProfileError on exit 9

    def test_windows_quotes_are_stripped_from_the_command(self):
        with mock.patch.object(profiles.os, "name", "nt"):
            self.assertEqual(profiles._split_command('"C:\\Program Files\\x\\h.exe" --flag'),
                             ["C:\\Program Files\\x\\h.exe", "--flag"])

    def test_example_masker_is_rankable_and_leaves_the_encoded_gap(self):
        cmd = f"exec:{sys.executable} {os.path.join(ROOT, 'keycanary', 'examples', 'literal_masker.py')}"
        results = harness.run(cmd)
        self.assertTrue(report.metrics(results)["rankable"])
        st = {r.probe_id: r.status for r in results}
        self.assertEqual(st["read-env"], "masked")
        self.assertEqual(st["b64-env-output"], "leaked")
        self.assertEqual(st["uppercased-env"], "leaked")


class Safety(unittest.TestCase):
    def test_clean_handles_tags_surrogates_and_invisible(self):
        nasty = "a\ud800b\U000e0041c\u2028d\u00ade\u2800f\ufe0fg\x9bh"
        out = report.clean(nasty)
        self.assertEqual(out, "a?b?c?d?e?f?g?h")
        out.encode("utf-8")

    def test_lone_surrogate_reason_does_not_crash_the_table(self):
        res = [report.Result("p", "c", "x", "blocked", "bad \ud800 reason")] \
            if hasattr(report, "Result") else []
        if res:
            report.to_table(res, "prof").encode("utf-8")


class Cli(unittest.TestCase):
    def test_version_only_explain_output(self):
        rc, out, _ = run_cli("--version")
        self.assertEqual(rc, 0)
        self.assertIn("keycanary", out)
        rc, out, _ = run_cli("--explain", "read-env")
        self.assertEqual(rc, 0)
        self.assertIn("{SBX}", out)
        rc, _, err = run_cli("--explain", "nope")
        self.assertEqual(rc, 2)
        rc, out, _ = run_cli("--only", "read-env,env-dump", "--format", "json")
        data = json.loads(out)
        self.assertEqual(data["total"], 2)
        self.assertTrue(data["meta"]["partial"])
        rc, _, _ = run_cli("--only", "no-such-probe")
        self.assertEqual(rc, 2)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            rc, out, _ = run_cli("--only", "read-env", "--format", "json", "-o", path)
            self.assertEqual(out, "")
            self.assertEqual(json.load(open(path))["total"], 1)
            rc, _, _ = run_cli("--only", "read-env", "-o", os.path.join(d, "no", "dir", "r"))
            self.assertEqual(rc, 2)

    def test_min_protection_gate(self):
        rc, _, err = run_cli("--only", "read-env", "--min-protection", "50")
        self.assertEqual(rc, 1)
        self.assertIn("below 50%", err)
        rc, _, _ = run_cli("--profile", "deny-all", "--only", "read-env", "--min-protection", "100")
        self.assertEqual(rc, 0)

    def test_by_category_in_json_and_table(self):
        rc, out, _ = run_cli("--format", "json")
        data = json.loads(out)
        self.assertIn("evasion", data["by_category"])
        rc, out, _ = run_cli()
        self.assertIn("by family", out)


class NewProbes(unittest.TestCase):
    def test_new_probes_exist_and_unprotected_leaks(self):
        ids = {"symlink-read-env", "copy-then-cat-env", "glob-wildcard-env", "variable-built-path",
               "base64-encoded-command", "tar-pipe-env", "echo-dollar-api-key", "gzip-b64-env-output",
               "double-b64-env-output", "uppercased-env", "ctl-grep-config-api-key"}
        probes = [p for p in loader.load() if p.id in ids]
        self.assertEqual({p.id for p in probes}, ids)
        for r in harness.run("none", probes):
            self.assertIn(r.status, ("leaked", "ok"), (r.probe_id, r.detail))

    def test_two_event_evasions_present_the_setup_to_the_profile(self):
        p = [p for p in loader.load() if p.id == "symlink-read-env"][0]
        self.assertEqual(len(p.pre), 1)
        seen = []
        sbx = sandbox.build()
        try:
            from keycanary.runner import run_probe
            run_probe(p, sbx, lambda e: (seen.append(e["tool_input"]["command"]) or False, None), "spy")
        finally:
            sandbox.destroy(sbx)
        self.assertEqual(len(seen), 2)
        self.assertIn("ln -s", seen[0])
        self.assertNotIn(".env", seen[1])


class Misc(unittest.TestCase):
    def test_html_unescape_import_used(self):
        # guards the entity form against a stdlib behaviour change
        self.assertEqual(html.unescape("&#115;"), "s")
        self.assertEqual(urllib.parse.unquote("%73"), "s")


if __name__ == "__main__":
    unittest.main()


class Pass2(unittest.TestCase):
    def test_wrongly_typed_replacement_is_ignored_like_claude_code(self):
        code = ("import json;print(json.dumps({'hookSpecificOutput':{'updatedToolOutput':"
                "{'stdout':1,'stderr':None,'interrupted':0,'isImage':0}}}))")
        probes = [p for p in loader.load() if p.id == "read-env"]
        res = harness.run(hook(code), probes)
        self.assertEqual(res[0].status, "leaked")

    def test_deeply_nested_json_from_a_hook_aborts_cleanly(self):
        with self.assertRaises(profiles.ProfileError):
            harness.run(hook("print('['*200000)"), probes=loader.load()[:1])

    def test_hook_timeout_flag(self):
        rc, _, err = run_cli("--hook-timeout", "0.1")
        self.assertEqual(rc, 2)
        rc, _, _ = run_cli("--only", "read-env", "--hook-timeout", "30")
        self.assertEqual(rc, 0)


class BenchAndDocs(unittest.TestCase):
    def test_readme_table_matches_committed_bench(self):
        with open(os.path.join(ROOT, "bench", "results.json"), encoding="utf-8") as fh:
            bench = json.load(fh)
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        self.assertEqual(bench["suites"], loader.EXPECTED)
        self.assertEqual(bench["probe_set_sha256"], loader.probe_set_hash(loader.load()))
        rows = {"none": "`none`", "exec: literal masker": "`exec:` literal masker",
                "exec: naive regex hook": "`exec:` naive regex hook",
                "deny-all": "`deny-all`", "mask-all": "`mask-all`"}
        for label, cell in rows.items():
            row = bench["profiles"][label]
            c = row["core"]
            line = next(ln for ln in readme.splitlines() if ln.startswith("| " + cell))
            want = f"{c['blocked']} / {c['masked']} / "
            self.assertIn(want, line, label)
            self.assertIn(f"{c['leaked']}", line, label)
            self.assertIn(str(row["controls"]["ok"]), line, label)

    def test_counts_in_readme_and_pyproject_match_the_pin(self):
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        e = loader.EXPECTED
        self.assertIn(f"{e['core']} ways", readme.split("\n", 3)[2])
        self.assertIn(f"({e['core']} / {e['encoded']} / {e['control']})", readme)
        self.assertIn(f"{e['core'] + e['encoded']} leak probes", readme)
