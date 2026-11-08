"""Round 5 tests: author line, packaging, hook-crash handling, fragment leaks,
property-style and differential checks of the judge, mutation-style sanity checks,
golden files for every output format, and hostile-environment CLI runs.

Fast on purpose (no full-suite exec runs). Standard library only; a `hypothesis`
test runs only when that package is installed. No contiguous secret literals:
canaries and encodings are built at runtime."""

from __future__ import annotations

import base64
import codecs
import glob
import json
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from keycanary import __author__, __version__, detect, harness, loader, profiles, report, runner  # noqa: E402
from keycanary.runner import Result  # noqa: E402

AUTHOR = "Calas Automations Inc."
GOLDEN = os.path.join(HERE, "golden")


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def run_cli(*args: str, env: dict | None = None, cwd: str = ROOT) -> tuple[int, str, str]:
    e = dict(os.environ)
    e.update(env or {})
    e["PYTHONPATH"] = ROOT + os.pathsep + e.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "keycanary", *args], cwd=cwd, env=e,
                          capture_output=True, timeout=300)
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def hook_cmd(code: str, d: str) -> str:
    path = os.path.join(d, "h o o k.py")  # a space in the path on purpose
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(code))
    return f'exec:"{sys.executable}" "{path}"'


class AuthorLine(unittest.TestCase):
    """The maintainer is exactly "Calas Automations Inc." everywhere it is named."""

    def test_pyproject_authors_and_no_maintainer_email(self):
        text = read("pyproject.toml")
        self.assertRegex(text, r'authors\s*=\s*\[\s*\{\s*name\s*=\s*"Calas Automations Inc\."\s*\}\s*\]')
        self.assertNotIn("email", text.lower())
        self.assertNotIn("calasdan", text)

    def test_no_package_urls_while_repo_visibility_is_unsettled(self):
        self.assertNotRegex(read("pyproject.toml"), r"(?m)^\[project\.urls\]")

    def test_license_copyright_line(self):
        self.assertIn(f"Copyright (c) 2026 {AUTHOR}", read("LICENSE"))

    def test_module_and_cli_carry_the_author(self):
        self.assertEqual(__author__, AUTHOR)
        rc, out, _ = run_cli("--version")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), f"keycanary {__version__} ({AUTHOR})")

    def test_report_tool_metadata(self):
        res = [Result("p", "c", "x", "leaked", "d")]
        driver = json.loads(report.to_sarif(res, "x"))["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["organization"], AUTHOR)
        self.assertIn(AUTHOR, report.to_junit(res, "x"))
        self.assertEqual(json.loads(report.to_json(res, "x"))["meta"]["author"], AUTHOR)

    def test_no_stale_owner_labels_in_tracked_text(self):
        bad = re.compile(r"Dan Calas|DC Enterprises|\bdan@", re.I)
        for rel in ("README.md", "CHANGELOG.md", "pyproject.toml", "LICENSE",
                    os.path.join("docs", "ROUND5.md")):
            path = os.path.join(ROOT, rel)
            if os.path.exists(path):
                self.assertIsNone(bad.search(read(rel)), rel)


class VersionAndPackaging(unittest.TestCase):
    def test_version_is_the_same_everywhere(self):
        m = re.search(r'^version\s*=\s*"([^"]+)"', read("pyproject.toml"), re.M)
        self.assertEqual(m.group(1), __version__)
        top = re.search(r"^## (\d+\.\d+\.\d+)", read("CHANGELOG.md"), re.M)
        self.assertEqual(top.group(1), __version__)
        if os.path.exists(os.path.join(ROOT, "PUBLISH-CHECKLIST.md")):
            self.assertIn(__version__, read("PUBLISH-CHECKLIST.md"))

    def test_examples_and_marker_ship_inside_the_package(self):
        text = read("pyproject.toml")
        for needle in ("examples/*.py", "probes/*.json", "py.typed"):
            self.assertIn(needle, text)
        for f in ("naive_hook.py", "literal_masker.py"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, "keycanary", "examples", f)), f)
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "keycanary", "py.typed")))

    def test_example_profiles_run_from_the_package_not_the_checkout(self):
        for name in profiles.EXAMPLES:
            prof = profiles.get(name)
            self.assertTrue(callable(prof))
        self.assertIn("example-literal-masker", profiles.AVAILABLE)

    def test_readme_has_no_checkout_only_commands(self):
        readme = read("README.md")
        self.assertNotIn("examples/naive_hook.py", readme.replace("keycanary/examples/", ""))
        self.assertNotIn("git clone", readme)           # the repository's visibility is not settled
        self.assertNotIn("github.com/calasdan-sketch", readme)

    def test_no_runtime_dependencies(self):
        self.assertRegex(read("pyproject.toml"), r"(?m)^dependencies\s*=\s*\[\s*\]")


class HookCrashIsNotAProtection(unittest.TestCase):
    """Python exits 2 for a missing script and argparse exits 2 on a bad flag; 2 also
    means "block" to a hook. A crash must never score as perfect protection."""

    PROBES = ["read-env", "ctl-echo"]

    def _probes(self):
        return [p for p in loader.load() if p.id in self.PROBES]

    def test_missing_script_aborts_with_plain_words(self):
        with self.assertRaises(profiles.ProfileError) as cm:
            profiles.get(f"exec:{sys.executable} /no/such/dir/hook.py")
        self.assertIn("hook script not found", str(cm.exception))

    def test_missing_relative_script_names_the_folder(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(profiles.ProfileError) as cm:
            old = os.getcwd()
            os.chdir(d)
            try:
                profiles.get(f"exec:{sys.executable} examples/naive_hook.py")
            finally:
                os.chdir(old)
        self.assertIn("folder you ran keycanary in", str(cm.exception))

    def test_inline_code_with_a_slash_is_not_mistaken_for_a_missing_script(self):
        for cmd in (f'exec:{sys.executable} -c "print(1/2)"', f"exec:{sys.executable} -m json.tool",
                    f"exec:{sys.executable} -X utf8 -c pass"):
            self.assertTrue(callable(profiles.get(cmd)), cmd)

    def test_windows_would_run_a_command_given_without_its_extension(self):
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "hook")
            open(exe + ".CMD", "w").close()
            with mock.patch.object(profiles.os, "name", "nt"), \
                    mock.patch.dict(os.environ, {"PATHEXT": ".COM;.EXE;.CMD"}):
                self.assertTrue(profiles._exists(exe))
                self.assertFalse(profiles._exists(os.path.join(d, "nothing")))

    def test_traceback_and_exit_2_is_a_crash_not_a_block(self):
        with tempfile.TemporaryDirectory() as d:
            cmd = hook_cmd("import sys\nraise RuntimeError('boom')\n", d)
            # python exits 1 on an uncaught exception, so force the exit-2 shape
            cmd2 = hook_cmd("import sys\nsys.stderr.write('Traceback (most recent call last):\\n  boom\\n')\n"
                            "sys.exit(2)\n", d)
            with self.assertRaises(profiles.ProfileError):
                harness.run(cmd, self._probes())
            with self.assertRaises(profiles.ProfileError) as cm:
                harness.run(cmd2, self._probes())
            self.assertIn("reads like a crash", str(cm.exception))

    def test_a_deliberate_exit_2_with_a_reason_still_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            cmd = hook_cmd("import sys\nsys.stderr.write('blocked: secret file')\nsys.exit(2)\n", d)
            res = {r.probe_id: r for r in harness.run(cmd, self._probes())}
        self.assertEqual(res["read-env"].status, "blocked")
        self.assertEqual(res["ctl-echo"].status, "overblocked")

    def test_cli_exit_code_for_a_mistyped_hook_is_2_not_0(self):
        rc, out, err = run_cli("--profile", f"exec:{sys.executable} nope/missing_hook.py", "--fail-on-leak")
        self.assertEqual(rc, 2)
        self.assertIn("hook script not found", err)
        self.assertNotIn("Traceback", err)

    def test_leak_gates_do_not_pass_a_deny_everything_hook(self):
        for gate in (["--fail-on-leak"], ["--max-leaked", "3"], ["--min-protection", "50"]):
            rc, _, err = run_cli("--profile", "deny-all", *gate)
            self.assertEqual(rc, 1, gate)
            self.assertIn("harmless call", err)

    def test_core_only_runs_have_no_controls_and_are_unchanged(self):
        rc, _, _ = run_cli("--profile", "deny-all", "--suite", "core", "--fail-on-leak")
        self.assertEqual(rc, 0)


class Fragments(unittest.TestCase):
    CAN = "sk-" + "canary" + "-" + "0123456789abcdef"

    def test_a_fragment_of_the_key_is_a_leak(self):
        self.assertIn("fragment", detect.find_leak("token starts 01234567 ...", self.CAN))
        self.assertIn("fragment", detect.find_leak("tail: 89ABCDEF", self.CAN))   # case-insensitive
        self.assertIn("fragment", detect.find_leak("0 1 2 3 4 5 6 7", self.CAN))   # spaced out

    def test_short_fragments_and_other_text_are_not(self):
        self.assertIsNone(detect.find_leak("0123456 only seven", self.CAN))
        self.assertIsNone(detect.find_leak("sk-canary-", self.CAN))
        self.assertIsNone(detect.find_leak("sk-canary-XXXX", self.CAN))

    def test_whole_key_verdicts_are_unchanged(self):
        self.assertEqual(detect.find_leak(self.CAN, self.CAN), "plain")
        self.assertEqual(detect.find_leak(self.CAN[::-1], self.CAN), "reversed")

    def test_a_masker_that_leaves_half_the_key_is_caught_end_to_end(self):
        probe = [p for p in loader.load() if p.id == "read-env"]
        half = textwrap.dedent("""
            import json, os, sys
            e = json.load(sys.stdin)
            if e.get("hook_event_name") == "PostToolUse":
                s = os.environ["KEYCANARY_CANARY"]
                r = e["tool_response"]
                new = {k: (v.replace(s[:-8], "***") if isinstance(v, str) else v) for k, v in r.items()}
                print(json.dumps({"hookSpecificOutput": {"updatedToolOutput": new}}))
            """)
        with tempfile.TemporaryDirectory() as d:
            res = harness.run(hook_cmd(half, d), probe)
        self.assertEqual(res[0].status, "leaked")
        self.assertIn("fragment", res[0].detail)


def _rand_canary(rng: random.Random) -> str:
    return "sk-" + "canary" + "-" + "".join(rng.choice("0123456789abcdef") for _ in range(16))


def _noise(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz \n:=.{}\"") for _ in range(n))


class JudgeProperties(unittest.TestCase):
    """Seeded generators (no external package): the judge finds the key however it
    is wrapped, and never fires on text that cannot contain it."""

    ENCODERS = {
        "plain": lambda s: s,
        "base64": lambda s: base64.b64encode(s.encode()).decode(),
        "base64url": lambda s: base64.urlsafe_b64encode(s.encode()).decode(),
        "base32": lambda s: base64.b32encode(s.encode()).decode(),
        "hex": lambda s: s.encode().hex(),
        "reversed": lambda s: s[::-1],
        "rot13": lambda s: codecs.encode(s, "rot_13"),
        "upper": lambda s: s.upper(),
    }

    def test_every_encoding_is_found_in_any_surrounding_text(self):
        rng = random.Random(20261108)
        for _ in range(60):
            can = _rand_canary(rng)
            for name, enc in self.ENCODERS.items():
                body = enc(_noise(rng, rng.randint(0, 5)) + can + _noise(rng, rng.randint(0, 5)))
                if name in ("reversed", "rot13", "upper"):
                    body = enc(can)
                text = _noise(rng, rng.randint(0, 30)) + "\n" + body + "\n" + _noise(rng, rng.randint(0, 30))
                self.assertIsNotNone(detect.find_leak(text, can), (name, can, text))

    def test_text_without_the_key_is_never_flagged(self):
        rng = random.Random(7)
        for _ in range(300):
            can = _rand_canary(rng)
            text = _noise(rng, rng.randint(0, 400))
            self.assertIsNone(detect.find_leak(text, can), text)

    def test_a_different_canary_is_not_a_leak(self):
        rng = random.Random(11)
        for _ in range(100):
            a, b = _rand_canary(rng), _rand_canary(rng)
            shares_a_fragment = any(a[10:][i:i + 8] in b for i in range(9))
            if a != b and not shares_a_fragment:
                self.assertIsNone(detect.find_leak(b, a))

    def test_clean_is_total_and_safe_for_any_text(self):
        rng = random.Random(3)
        pool = [chr(i) for i in list(range(0, 300)) + [0x202e, 0x200b, 0xd800, 0xe0041, 0x2028, 0xfeff]]
        for _ in range(300):
            text = "".join(rng.choice(pool) for _ in range(rng.randint(0, 40)))
            out = report.clean(text)
            out.encode("utf-8")
            bad = "[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u200b-\u200f]"
            self.assertIsNone(re.search(bad, out))
            self.assertNotIn("\n", out)

    def test_huge_output_is_bounded(self):
        can = "sk-" + "canary" + "-" + "0123456789abcdef"
        blob = base64.b64encode(os.urandom(3_000_000)).decode()
        t = time.monotonic()
        self.assertIsNone(detect.find_leak(blob, can))
        self.assertLess(time.monotonic() - t, 30)

    def test_hypothesis_clean_never_raises_if_installed(self):
        try:
            from hypothesis import given, settings
            from hypothesis import strategies as st
        except ImportError:
            self.skipTest("hypothesis is not installed")

        @settings(max_examples=200, deadline=None)
        @given(st.text())
        def prop(t):
            report.clean(t).encode("utf-8")

        prop()


class DifferentialAgainstReference(unittest.TestCase):
    """A deliberately simple reference judge (encode the key N ways, look for the
    result in the output) must agree with detect.find_leak on every form the
    reference knows about."""

    @staticmethod
    def reference(output: str, secret: str) -> bool:
        raw = secret.encode()
        variants = {secret, secret[::-1], codecs.encode(secret, "rot_13"), secret.upper(), secret.lower(),
                    raw.hex(), raw.hex().upper(), base64.b64encode(raw).decode(),
                    base64.urlsafe_b64encode(raw).decode(), base64.b32encode(raw).decode().rstrip("=")}
        return any(v in output for v in variants)

    def test_agrees_on_random_outputs(self):
        rng = random.Random(99)
        for _ in range(200):
            can = _rand_canary(rng)
            if rng.random() < 0.5:
                enc = rng.choice(list(JudgeProperties.ENCODERS.values()))
                out = _noise(rng, 20) + enc(can) + _noise(rng, 20)
            else:
                out = _noise(rng, 80)
            if self.reference(out, can):
                self.assertIsNotNone(detect.find_leak(out, can), out)
            else:
                self.assertIsNone(detect.find_leak(out, can), out)


class MutationSanity(unittest.TestCase):
    """Flip a key condition and confirm the behaviour tests would notice."""

    CAN = "sk-" + "canary" + "-" + "0123456789abcdef"

    def test_if_the_judge_were_blind_masking_would_be_credited_wrongly(self):
        # mutant: find_leak always None. The differential rule then reports n/a, so
        # the real, working judge is what separates leaked from n/a.
        probe = [p for p in loader.load() if p.id == "read-env"]
        self.assertEqual(harness.run("none", probe)[0].status, "leaked")
        with mock.patch.object(runner.detect, "find_leak", return_value=None):
            self.assertEqual(harness.run("none", probe)[0].status, "n/a")

    def test_mask_all_can_not_earn_masked_if_raw_check_is_skipped(self):
        # real behaviour: mask-all on read-env is "masked" only because the raw output had the key
        probe = [p for p in loader.load() if p.id == "read-env"]
        self.assertEqual(harness.run("mask-all", probe)[0].status, "masked")
        real = detect.find_leak
        calls = []

        def spy(out, secret):
            calls.append(out)
            return real(out, secret)

        with mock.patch.object(runner.detect, "find_leak", side_effect=spy):
            harness.run("mask-all", probe)
        self.assertEqual(len(calls), 2)  # raw output first, then what the model sees

    def test_dropping_the_whitespace_rule_is_noticed(self):
        spaced = " ".join(self.CAN)
        self.assertEqual(detect.find_leak(spaced, self.CAN), "split by whitespace")
        with mock.patch.object(detect, "_WS", re.compile(r"(?!x)x")):
            self.assertNotEqual(detect.find_leak(spaced, self.CAN), "split by whitespace")

    def test_dropping_the_fragment_rule_is_noticed(self):
        self.assertIsNotNone(detect.find_leak("x 01234567 y", self.CAN))
        with mock.patch.object(detect, "_partial", return_value=None):
            self.assertIsNone(detect.find_leak("x 01234567 y", self.CAN))

    def test_controls_flip_the_verdict_to_not_rankable(self):
        ok = [Result("c", "x", "p", "ok", "", "control")]
        bad = ok + [Result("d", "x", "p", "overblocked", "", "control")]
        self.assertTrue(report.metrics(ok)["rankable"])
        self.assertFalse(report.metrics(bad)["rankable"])


def _fixed_results() -> list[Result]:
    return [
        Result("env-dump", "env dumps", "demo", "leaked", "canary in agent-visible output (plain)"),
        Result("read-env", "direct file read", "demo", "blocked", "no \x1b[31mreds\x1b[0m \u202ehere"),
        Result("b64-env-output", "encoded", "demo", "masked",
               "canary was in the raw output and is gone", "encoded"),
        Result("keychain-read", "keystore", "demo", "n/a", "tool missing"),
        Result("ctl-echo", "benign control", "demo", "ok", "benign call passed through unchanged", "control"),
        Result("ctl-ls", "benign control", "demo", "overblocked", "benign call denied: <&> \"x\"", "control"),
    ]


class Golden(unittest.TestCase):
    """Byte-exact output for every format on a fixed set of results. Regenerate
    deliberately with  UPDATE_GOLDEN=1 python -m unittest tests.test_round5.Golden"""

    @staticmethod
    def _norm(text: str) -> str:
        return text.replace(__version__, "{VERSION}")

    def _check(self, name: str, text: str) -> None:
        text = self._norm(text) + "\n"
        path = os.path.join(GOLDEN, name)
        if os.environ.get("UPDATE_GOLDEN") == "1":
            os.makedirs(GOLDEN, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        with open(path, encoding="utf-8", newline="") as fh:
            self.assertEqual(fh.read(), text, f"{name} changed; if intended, UPDATE_GOLDEN=1")

    def test_table(self):
        self._check("table.txt", report.to_table(_fixed_results(), "demo"))

    def test_markdown(self):
        self._check("markdown.md", report.to_markdown(_fixed_results(), "demo"))

    def test_junit_is_golden_and_wellformed(self):
        import xml.etree.ElementTree as ET
        text = report.to_junit(_fixed_results(), "demo")
        ET.fromstring(text.encode("utf-8"))
        self._check("junit.xml", text)

    def test_sarif(self):
        text = report.to_sarif(_fixed_results(), "demo")
        doc = json.loads(text)
        self.assertEqual(doc["version"], "2.1.0")
        self._check("sarif.json", text)

    def test_json(self):
        doc = json.loads(report.to_json(_fixed_results(), "demo", probe_hash="0" * 64))
        doc["meta"].update(python="X", platform="X")
        self._check("report.json", json.dumps(doc, indent=2, sort_keys=True))

    def test_golden_text_has_no_terminal_control(self):
        for name in os.listdir(GOLDEN):
            body = open(os.path.join(GOLDEN, name), encoding="utf-8").read()
            self.assertIsNone(re.search("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e]", body), name)


class HostileEnvironment(unittest.TestCase):
    def test_console_that_cannot_show_unicode_does_not_traceback(self):
        rc, out, err = run_cli("--suite", "control", env={"PYTHONIOENCODING": "ascii"})
        self.assertEqual(rc, 0, err)
        self.assertNotIn("Traceback", err)
        out.encode("ascii", "replace")

    def test_c_locale(self):
        rc, _, err = run_cli("--only", "read-env", env={"LC_ALL": "C", "LANG": "C"})
        self.assertEqual(rc, 0, err)

    def test_baseline_that_is_not_a_report_is_a_plain_error(self):
        with tempfile.TemporaryDirectory() as d:
            for body in ("[1]", "{}", '{"results": 3}', '{"results": [1], "meta": {"probe_set_sha256": "x"}}',
                         "not json", ""):
                path = os.path.join(d, "b.json")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
                rc, _, err = run_cli("--only", "read-env", "--baseline", path)
                self.assertEqual(rc, 2, body)
                self.assertNotIn("Traceback", err, body)
                self.assertIn("gate error", err, body)
            rc, _, err = run_cli("--only", "read-env", "--baseline", os.path.join(d, "missing.json"))
            self.assertEqual(rc, 2)
            self.assertNotIn("Traceback", err)

    def test_baseline_with_bad_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.json")
            with open(path, "wb") as fh:
                fh.write(b"\xff\xfe\x00bad")
            rc, _, err = run_cli("--only", "read-env", "--baseline", path)
            self.assertEqual(rc, 2)
            self.assertNotIn("Traceback", err)

    def test_working_directory_with_spaces_and_unicode(self):
        with tempfile.TemporaryDirectory(prefix="kc sp\u00e4ce ") as d:
            rc, out, err = run_cli("--only", "read-env,ctl-echo", "--format", "json", cwd=d)
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["total"], 2)

    def test_two_runs_at_once_do_not_collide(self):
        env = dict(os.environ, PYTHONPATH=ROOT)
        procs = [subprocess.Popen([sys.executable, "-m", "keycanary", "--only", "read-env,env-dump",
                                   "--format", "json"], cwd=ROOT, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
        for p in procs:
            out, err = p.communicate(timeout=120)
            self.assertEqual(p.returncode, 0, err)
            self.assertEqual(json.loads(out)["summary"]["leaked"], 2)

    @unittest.skipIf(os.name == "nt", "POSIX signals")
    def test_ctrl_c_stops_cleanly_and_does_not_leave_the_hook_running(self):
        self._interrupt(signal.SIGINT)

    @unittest.skipIf(os.name == "nt", "POSIX signals")
    def test_a_ci_cancel_sigterm_also_cleans_up(self):
        self._interrupt(signal.SIGTERM)

    def _interrupt(self, sig):
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "pid")
            cmd = hook_cmd(f"""
                import os, time
                open({pidfile!r}, "w").write(str(os.getpid()))
                time.sleep(60)
                """, d)
            tmp = os.path.join(d, "tmp")
            os.mkdir(tmp)           # sandboxes are created here, so leftovers are ours alone
            env = dict(os.environ, PYTHONPATH=ROOT, TMPDIR=tmp, TEMP=tmp, TMP=tmp)
            argv = [sys.executable, "-m", "keycanary", "--profile", cmd, "--only", "read-env"]
            proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(100):
                if os.path.exists(pidfile) and open(pidfile).read():
                    break
                time.sleep(0.1)
            proc.send_signal(sig)
            out, err = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 130, err)
            self.assertNotIn(b"Traceback", err)
            pid = int(open(pidfile).read())
            time.sleep(0.5)
            self.assertEqual(glob.glob(os.path.join(tmp, "keycanary-*")), [], "sandbox left behind")
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    @unittest.skipIf(os.name == "nt", "POSIX pipes")
    def test_reader_that_goes_away_is_not_a_traceback(self):
        env = dict(os.environ, PYTHONPATH=ROOT)
        proc = subprocess.Popen([sys.executable, "-m", "keycanary", "--list"], cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdout.close()          # `keycanary --list | head -0`
        err = proc.stderr.read()
        proc.wait(timeout=60)
        self.assertNotIn(b"Traceback", err)
        self.assertNotIn(b"Exception ignored", err)

    def test_hook_that_prints_garbage_aborts(self):
        with tempfile.TemporaryDirectory() as d:
            cmd = hook_cmd("print('{not json')\n", d)
            rc, _, err = run_cli("--profile", cmd, "--only", "read-env")
            self.assertEqual(rc, 2)
            self.assertNotIn("Traceback", err)

    def test_windows_style_command_splitting_keeps_spaces(self):
        with mock.patch.object(profiles.os, "name", "nt"):
            self.assertEqual(profiles._split_command("'C:\\Program Files\\h k\\x.exe' -a"),
                             ["C:\\Program Files\\h k\\x.exe", "-a"])


if __name__ == "__main__":
    unittest.main()
