# Changelog

## 0.2.0 (unreleased)

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
