# Round 5

Scope: the "stranger's first hour" packaging pass (the package was never
published and `docs/ROUND4.md` does not exist) plus three field specialists. Pass
B re-attacked the new code. Maintainer name everywhere: **Calas Automations Inc.**

**How this was run, honestly.** No sub-agents were available in this session, so
one reviewer played each role in sequence and ran real commands for each. Every
finding below names the command that showed it. The machine was heavily loaded by
other work (load average above 20), so wall-clock times are noisy; CPU time is
quoted where it matters. Nothing was pushed, published, tagged or uploaded.

## Baseline (before any change)

| | result |
|---|---|
| tests | `python -m pytest -q tests`: 60 passed, 186 s |
| lint | `ruff check .`: clean |
| scores | `python bench/run.py --check`: matches (79 s); `none` 0/0/61/9, encoded 17/17, controls 14/14 |
| build | `python -m build` + `twine check`: pass; wheel 29 files |
| registry | `pip index versions keycanary` and `leakbench`: "No matching distribution" (unverified whether the index was filtered) |

## Author line

Already "Calas Automations Inc." in `pyproject.toml` and `LICENSE`; added
`__author__`, `--version` ("keycanary 0.2.0 (Calas Automations Inc.)"), JSON
`meta.author`, SARIF `organization`, JUnit properties, README footer.
Re-grep of the tree for the old owner-name variants (the patterns are in the test): no hits; a test pins this. Pinned by `tests/test_round5.py::AuthorLine`.
Proof from the built artifact:

    unzip -p dist/keycanary-0.2.0-py3-none-any.whl '*/METADATA' | head -6
    -> Author: Calas Automations Inc.   (no Author-email line)
    unzip -p dist/keycanary-0.2.0-py3-none-any.whl '*/licenses/LICENSE' | grep Copyright
    -> Copyright (c) 2026 Calas Automations Inc.

URLs: the repository's visibility is not settled, so `[project.urls]` was removed
and the README no longer says `git clone ...` or links the sibling repository.

## Specialists and findings

### 1. Honeytoken / secrets-leak engineer

| finding | command that proved it | status |
|---|---|---|
| A masker that hides only part of the key scored `masked`. The judge ignored fragments. | hook replacing `canary[:-8]` with `***`, then `keycanary --only read-env` (now `tests/test_round5.py::Fragments::test_a_masker_that_leaves_half_the_key_is_caught_end_to_end`) | fixed: 8+ characters of the key's random part = `leaked (fragment ...)`; tried only after every whole-key form failed, so no earlier verdict moved (bench counts identical) |
| False-positive risk of that rule | seeded run: 300 random outputs, 100 canary pairs (`JudgeProperties`) | none found; a real run's key is random per run. One existing test used the fixture canary's own hex as "ordinary text" and was changed (fixture artifact) |
| Judge vs a naive reference implementation | `DifferentialAgainstReference` (200 seeded cases) | agrees |
| Judge holds up on 4 MB of random base64 | `JudgeProperties::test_huge_output_is_bounded` | bounded |
| Canary that reports back when used (a real honeytoken service) | not built | needs network or a paid service; the README promises none |

### 2. AppSec incident responder

| finding | command that proved it | status |
|---|---|---|
| **A mistyped hook path scored perfect protection.** Python exits 2 for a missing script; 2 means "block" to a hook. 14 "overblocked" rows, exit 0 with `--fail-on-leak`. | `keycanary --profile "exec:python examples/naive_hook.py" --suite control` from a folder without `examples/` | fixed: missing script aborts (exit 2); exit 2 with crash-like stderr (traceback, "can't open file", "command not found", usage line) aborts; a plain reason still blocks |
| **A deny-everything hook passed CI.** | `keycanary --profile deny-all --fail-on-leak; echo $?` printed 0 | fixed: leak gates also fail when a control was broken (exit 1). Behaviour change, documented. Existing test that asserted the old behaviour was rewritten |
| Ctrl-C: traceback, and the hook kept running (own process group) | `timeout -s INT 2 keycanary --profile "exec:sleep 1"` | fixed (exit 130, hook killed) |
| CI cancel (SIGTERM) left the sandbox folder and the hook | SIGTERM during a run, then `ls /tmp/keycanary-*` | fixed (same path as Ctrl-C) |
| `--baseline` with a JSON list crashed with AttributeError | `echo '[1]' > b.json; keycanary --suite control --baseline b.json` | fixed (exit 2, plain message); bad bytes and rows without `probe_id` also covered |
| SARIF results have no location | read of `report.to_sarif` | partly fixed: logical location + properties added. Whether GitHub code scanning accepts a result with no file location is **unverified** (never uploaded) |
| Child failed to start once under load, silently became `n/a` | one flaky run of `ExecProfile.test_exit_2_blocks` (5 of 14 instead of 14); cause not proven | mitigated: start is retried twice |

### 3. DX writer (first hour, README only)

| finding | command that proved it | status |
|---|---|---|
| The README's example hooks are not in the wheel or the sdist, so `exec:python examples/naive_hook.py` fails after `pip install` | `unzip -l dist/*.whl`; run from an installed wheel in `/tmp` | fixed: examples ship in `keycanary/examples/`, run as `--profile example-literal-masker` / `example-naive-hook` |
| README said `git clone https://github.com/...`, which claims a public repo | read | removed |
| `--help` had no examples or exit codes | `keycanary --help` | added |
| Unshowable character crashed the table | `PYTHONIOENCODING=ascii keycanary --suite control` | fixed (prints `?`) |
| `keycanary | head` printed BrokenPipeError | `keycanary --explain read-env | head -3` | fixed (exit 141, silent) |
| Table gave no next step after the GAPS list | read | added `--explain <id>` pointer |
| "about 2 seconds" | timed under load: 1.2 to 2.5 s of CPU, 6 to 24 s wall | README now says "a few seconds" |

## Packaging proof (offline)

    python -m build --outdir dist2 .            # sdist + wheel
    python -m twine check dist2/*               # PASSED, PASSED
    unzip -l dist2/*.whl                        # adds keycanary/examples/*.py and py.typed; no tests, no junk
    for py in python3.11 python3.12 python3.13; do
      $py -m venv v && v/bin/pip install --no-index dist2/*.whl      # non-editable
      (cd /tmp && v/bin/keycanary --version)                         # keycanary 0.2.0 (Calas Automations Inc.)
      v/bin/keycanary --profile example-literal-masker --suite control --fail-on-leak   # exit 0
      v/bin/keycanary --profile "exec:python examples/typo.py" --fail-on-leak           # exit 2, plain message
    done

`pip install .` from the folder (offline, `--no-build-isolation`, system setuptools) also
works; with network it would fetch setuptools in an isolated build (not run).
The sdist unpacked in a scratch folder passes the Golden / AuthorLine / VersionAndPackaging /
Fragments tests there. Setuptools used to warn that `keycanary.probes` is "absent from
packages" (it was in 0.2.0 before this round too); the two data folders are now listed.

Dependencies: none declared, none needed (imports in the clean venvs succeed).
Metadata consistent: name, version (pyproject = `__version__` = top CHANGELOG
heading = checklist, pinned by `VersionAndPackaging`), author, license
expression MIT, `python_requires >=3.10`, classifiers 3.11-3.13 (the versions
run), no URLs. Found and fixed: the sdist lacked `tests/golden/*.xml|*.md`
(MANIFEST.in now includes them); CHANGELOG/bench/docs were missing from the sdist.

## Quality methods added

- Property-style tests with a seeded generator (the judge finds every encoding in
  any surrounding text; never fires on text without the key; `clean()` is total).
  A `hypothesis` test runs only if that package is installed (it was).
- Differential test against a small reference judge.
- Mutation-style sanity: blind judge, skipped raw check, dropped whitespace rule,
  dropped fragment rule, broken control each flip a specific verdict.
- Golden files for table, markdown, JUnit, SARIF and JSON (`tests/golden/`,
  regenerate with `UPDATE_GOLDEN=1`).
- Hostile environment: ASCII console, `LC_ALL=C`, a directory with spaces and a
  non-ASCII name, a path with spaces to the hook, 4 concurrent runs, Ctrl-C,
  SIGTERM, closed pipe, garbage baseline, garbage hook output.

## Results

| | before | after |
|---|---|---|
| tests | 60 passed | 113 passed (53 new) |
| `ruff check .` | clean | clean |
| committed scores (`bench/run.py --check`) | match | match (counts identical; probe hash unchanged) |
| CPU time, full default run | 1.3 to 2.0 s | 1.2 to 2.5 s (same range; load noise) |

Competitors re-read, read-only, on 2026-11-08: phantom-secrets README still states
210 of 450 exposed on a plain `.env` and 0 of 450 after `phantom init`, with
`python3 eval/leak-rate/harness.py` as the reproduction, and `phantom check --log`
as a transcript scanner. The fidelius site describes a Mac app (macOS 15 or later)
using `accio`. Not re-run: both are third-party figures. gitleaks and trufflehog
were not fetched (unverified).

## Scored ideas (value / differentiation / effort / risk, 1 to 5; effort and risk: lower is cheaper)

| # | idea | value | diff. | effort | risk | status |
|---|---|---|---|---|---|---|
| 1 | Crashed hook must abort, not count as a block | 5 | 3 | 2 | 1 | DONE |
| 2 | Leak gates fail when controls are broken | 5 | 4 | 1 | 2 | DONE |
| 3 | Ship example hooks in the wheel + `example-*` profiles | 4 | 2 | 2 | 1 | DONE |
| 4 | Fragment (8+ chars) detection | 4 | 4 | 2 | 2 | DONE |
| 5 | Console-safe output (no traceback on odd encodings) | 3 | 1 | 1 | 1 | DONE |
| 6 | Clean Ctrl-C / SIGTERM, kill the hook group, remove sandbox | 4 | 2 | 2 | 1 | DONE |
| 7 | Validate `--baseline` input | 3 | 1 | 1 | 1 | DONE |
| 8 | Drop unverifiable URLs / clone line | 3 | 1 | 1 | 1 | DONE |
| 9 | SARIF logical location, organization, properties | 3 | 2 | 1 | 2 | DONE (GitHub acceptance unverified) |
| 10 | JUnit properties (tool, author) | 2 | 1 | 1 | 1 | DONE |
| 11 | Golden files for all formats | 3 | 1 | 2 | 1 | DONE |
| 12 | Seeded property + differential judge tests | 4 | 2 | 2 | 1 | DONE |
| 13 | Mutation-style sanity tests (hand-written; no mutation tool run) | 3 | 2 | 2 | 1 | DONE |
| 14 | CI job: build, install the wheel, run the quick start | 4 | 2 | 1 | 1 | DONE (not run: no CI here) |
| 15 | `py.typed`, `MANIFEST.in`, 3.11-3.13 classifiers | 2 | 1 | 1 | 1 | DONE |
| 16 | `--explain <id>` pointer under GAPS; `--help` examples | 3 | 1 | 1 | 1 | DONE |
| 17 | Retry a failed child start | 2 | 1 | 1 | 1 | DONE |
| 18 | Per-gap "how to fix" text in reports | 4 | 4 | 3 | 4 (advice must be sourced, not invented) | NOT-DONE |
| 19 | Live honeytoken that reports use | 3 | 5 | 5 | 5 (network or paid) | NOT-DONE |
| 20 | Fragment search inside decoded layers (half the key, base64'd) | 3 | 3 | 2 | 2 | NOT-DONE |
| 21 | Secret split across separate tool calls (stateful judge) | 5 | 5 | 5 | 3 | NOT-DONE (earlier round too) |
| 22 | `keycanary scan-log FILE`: judge a real agent transcript | 5 | 4 | 3 | 2 | NOT-DONE (next round candidate) |
| 23 | Real `Read` result shape in the judge | 3 | 2 | 2 | 3 (shape unconfirmed) | NOT-DONE (earlier round too) |
| 24 | Profile for Claude Code's `sandbox.credentials` masking | 5 | 5 | 4 | 3 (needs a live Claude Code) | NOT-DONE (earlier round too) |
| 25 | Re-run StuntKey profiles on 70/17/14 | 3 | 2 | 1 | 1 | NOT-DONE (StuntKey not installed here; earlier round too) |
| 26 | Run on Windows and macOS | 5 | 1 | 2 | 1 | NOT-DONE (no such machine) |
| 27 | Run gitleaks / trufflehog for the comparison table | 2 | 2 | 2 | 1 | NOT-DONE (no binaries, no network) |
| 28 | Default smoke call so `--suite core` can spot a deny-all hook | 3 | 3 | 2 | 3 (changes core counts) | NOT-DONE (documented as a limit) |
| 29 | MCP tool-result and subagent-output probes | 4 | 4 | 4 | 2 | NOT-DONE |
| 30 | Run probes in parallel for slow `exec:` hooks | 3 | 1 | 3 | 3 (cross-probe files) | NOT-DONE |

## What I could not test

- Windows and macOS: not run. Static review only: `os.killpg`/`SIGKILL` are in the
  POSIX branch; `taskkill` for Windows; hook quotes stripped; extension-less
  commands accepted via `PATHEXT`; console encoding handled by `errors="replace"`.
  The new CI `package` job uses a shell expression for the venv path on Windows
  that was not run.
- Python 3.10 (the declared minimum): not installed; 3.11, 3.12 and 3.13 were run
  (wheel install + quick start on all three; the README's CI-gate commands on 3.11 only).
- A type checker: none installed (no mypy), so none was run.
- StuntKey profiles, gitleaks, trufflehog, GitHub code scanning upload, the live
  PyPI index (a filtered network would look the same as "no such package").
- Timing: the machine was under heavy load; wall-clock numbers are not a benchmark.
