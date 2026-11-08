# Changelog

## 0.2.0 (unreleased), round 5

Reviewed again as a honeytoken/secrets-leak engineer, an AppSec incident
responder and a docs/DX writer, plus a packaging pass (the "stranger's first
hour") because this package has never been published. Details and the commands
that proved each finding: `docs/ROUND5.md`. Probe set unchanged (70 / 17 / 14);
committed scores unchanged.

### Fixed
- **A crashed hook scored as perfect protection.** Python exits 2 for a missing
  script, and argparse exits 2 on a bad flag; 2 also means "block" to a hook, so
  `--profile "exec:python typo.py" --fail-on-leak` printed 14 "overblocked" rows
  and exited 0. A script path that does not exist, or exit 2 with error text that
  reads like a crash (traceback, "can't open file", "command not found", a usage
  line), now aborts the run (exit 2) with a plain message.
- **A hook that denies everything passed leak gates.** `--fail-on-leak`,
  `--max-leaked` and `--min-protection` now also fail when a harmless control was
  denied or altered. *Behaviour change*: `--profile deny-all --fail-on-leak` used
  to exit 0 and now exits 1. Core-only runs have no controls and are unchanged.
- The examples were not in the wheel or the sdist, so the README's
  `exec:python examples/naive_hook.py` could not work after `pip install`. They
  now ship inside the package (`keycanary/examples/`) and run as
  `--profile example-naive-hook` / `example-literal-masker`.
- A console that cannot show a character (`PYTHONIOENCODING=ascii`, legacy
  Windows code pages) crashed the table with a traceback; unshowable characters
  now print as `?`.
- Ctrl-C printed a traceback and left the hook process running (it has its own
  process group); a CI cancel (SIGTERM) left the sandbox folder behind. Now both:
  a one-line message, exit 130, the hook is killed, the sandbox is removed.
- A probe whose child process failed to start once (a runner out of processes or
  memory) became a silent `n/a`; the start is now retried twice. (Seen once as a
  test flake on a heavily loaded machine; the cause was not proven.)
- `keycanary | head` printed a BrokenPipeError traceback; now silent, exit 141.
- `--baseline` with a file that is not a keycanary report (a JSON list, rows
  without `probe_id`, bytes that are not UTF-8) crashed; now exit 2 with a message.

### Added
- **Fragment detection**: 8 or more characters of the key's random part in the
  output now count as a leak (`fragment`). A masker that hides only half the key
  used to score as masked. Reported only after every whole-key form failed, so no
  earlier verdict changed.
- `--version` and reports name the maintainer, Calas Automations Inc.
  (`__author__`, JSON `meta.author` and `meta.report_format`, SARIF
  `organization`, JUnit properties). SARIF results carry a logical location and
  properties. The table points at `--explain <id>` under the gaps.
- `--help` shows examples and the exit codes.
- Tests: property-style (seeded) and differential tests of the judge, mutation-style
  sanity tests, golden files for table / markdown / JUnit / SARIF / JSON,
  hostile-environment CLI runs, an author-line pin, a version-consistency pin.
- CI: a `package` job builds the wheel, installs it into a clean environment and
  runs the quick start from there.
- `py.typed`; `MANIFEST.in` (CHANGELOG, bench, docs, tests go into the sdist).

### Changed
- The package metadata no longer lists source/issue URLs: whether the repository
  is public is not settled, and a package page must not link somewhere a stranger
  cannot open. The README no longer shows a `git clone` line. Add the URLs back to
  `pyproject.toml` when it is public.
- Python 3.11, 3.12 and 3.13 classifiers added (those were run); 3.10 remains the
  declared minimum and was not run.

### Known limits
- Windows and macOS were not run. StuntKey profiles still not re-run.
- SARIF has not been uploaded to GitHub code scanning; whether it accepts a result
  with only a logical location is unverified.

## 0.2.0 (unreleased), round 3

Reviewed again as an attacker, a hook-protocol engineer, a process/CI reliability
engineer, a docs lead using only the README, a benchmark statistician and an
engineer from a competing tool. Probe set is now 70 / 17 / 14 (was 61 / 8 / 10);
scores from the earlier set are not comparable.

### Added
- **Judge**: finds the canary in a different letter case, with punctuation
  between characters, base64url, base32, and by decoding the output (up to three
  layers) through base64/base32/hex/percent/`\u`/`\x`/HTML entities/decimal codes
  and size-capped zlib/gzip. Work is bounded (printable-only recursion, byte
  budget, 2 MB inflate cap).
- **Probes**: 9 core (`symlink-read-env`, `copy-then-cat-env`,
  `glob-wildcard-env`, `variable-built-path`, `base64-encoded-command`,
  `tar-pipe-env`, `git-diff-no-index-env`, `ps-eww-env`, `echo-dollar-api-key`),
  9 encoded (url-safe/double/gzipped base64, base32, percent, dotted, od -c,
  decimal codes, upper-case), 4 controls (docs file named `environment.md`, a
  one-line Python program, a grep that names `API_KEY` in source, a listing of
  env file names). Setup steps can now be shell commands as well as writes.
- **exec adapter**: honours the deprecated top-level `decision: block`; `ask` and
  `defer` are reported as not blocked; sends Claude Code's common fields and
  `CLAUDE_PROJECT_DIR`; ignores a replacement output of the wrong shape or types
  (as Claude Code does); strips quotes from Windows command paths; caps hook
  output at 1 MB; `--hook-timeout`. Source: the hooks reference, read 2026-11-07.
- **CLI**: `--version`, `--only`, `--explain`, `--output`, `--min-protection`,
  `--hook-timeout`; per-family breakdown in table and JSON; JSON `meta.partial`.
- `bench/run.py` and committed `bench/results.json`; a test ties the README
  score table to it. `examples/literal_masker.py`, a rankable example hook.

### Fixed
- A hook (or probe) that left a background process holding its pipes made a run
  hang far past the timeout; children now run in their own process group and are
  killed as a group. Endless output is capped instead of filling memory. Probes
  no longer inherit the runner's stdin.
- A `Python` probe used `python` from `PATH`; it now uses the running interpreter.
- A hook printing deeply nested JSON crashed with a traceback (now exit 2).
- A wrongly typed `updatedToolOutput` crashed the judge (now ignored).
- Report text: Unicode tag characters, variation selectors, line/paragraph
  separators, soft hyphen, blank braille/hangul and lone surrogates are removed
  with the other control characters; a lone surrogate in a hook's reason used to
  crash printing.
- README: the detect-secrets figure (11 of 14) could not be reproduced and is
  replaced by a measured one (5 of 14); the `n/a` explanation listed the wrong
  causes; the `pipx run` quick start was not verifiable and the checkout path is
  now first.

### Changed
- Pinned set: 70 / 17 / 14. Probe hash changed. Sandbox gained `docs/` and
  `src/` files used by the new controls.
- Unprotected `none` now leaks 61 of 70 core (was 52 of 61) and 17 of 17 encoded.

### Known limits
- StuntKey profiles not re-run on the new set (StuntKey not installed here).
- Windows and macOS were not run this round.

## 0.2.0 (unreleased), rounds 1-2

Found by reviewing the benchmark as a secrets-management engineer, an agent
red-teamer, a benchmark statistician, a CI owner and a coding-agent vendor
engineer would.

### Added
- **Benign controls** (10): harmless calls that must pass untouched. A run that
  denies or alters any is printed NOT RANKABLE. Reference profiles `deny-all`
  and `mask-all` prove the benchmark cannot be gamed by blocking or blanking.
- **Encoded-exfiltration suite** (8) and an encoding-aware judge: the canary is
  found in base64 (any alignment, wrapped), hex, reversed, ROT13 and
  whitespace-split output. A masker that only matches the literal key no longer
  scores as masked.
- **`exec:<command>` profile**: score any tool that speaks the Claude Code hook
  protocol, in any language. Fails closed (bad command, crash, non-JSON output
  abort with exit 2).
- **CI gates and formats**: `--fail-on-leak`, `--max-leaked`, `--strict`,
  `--baseline`, `--repeat`, `--suite`, `--list`; `--format
  table|json|markdown|junit|sarif`. JSON reports carry the version, a SHA-256 of
  the probe definitions, platform and Python.
- Probe set pinned in code per suite (61 / 8 / 10); a mismatch aborts.
- Tests (30), ruff config, CI workflow, `examples/naive_hook.py`.

### Changed
- **Differential judging**: `masked` now needs the canary in the raw output; a
  command that never produced it is `n/a`. The old rule ("any `***` in the
  output means masked") is gone.
- **Event fidelity**: the three probes that put a script's output on a `Write`
  event are now two events (`Write`, then `Bash`). With this, the stuntkey hook
  no longer shows the three "gaps" the 0.1.0 README listed; those numbers were
  wrong.
- **Probe environment is minimal and host-independent.** 0.1.0 copied the whole
  host environment into every probe, so a bare `env` probe printed the runner's
  real tokens to the profile's post hook. Only the variables a shell needs are
  kept, plus the canaries.
- JSON `summary` counts leak probes only; benign controls are in `controls`.
  New fields: `metrics`, `meta`, `unstable`; each result has `suite`.
- Text from a profile is stripped of terminal-control, bidi and zero-width
  characters in every output format (including probe ids and categories).

### Known limits
- Still simulated tool calls, not a live model or agent harness.
- `Read` probes are judged with the Bash output shape; a profile's separate
  file-read hook shape is not modelled.
- gitleaks and trufflehog were not run (no network access to fetch binaries).
