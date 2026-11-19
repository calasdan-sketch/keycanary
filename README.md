# keycanary

**A benchmark of 64 ways an AI coding agent can leak an API key, written by the author of stuntkey (one of the tools it scores). Not independently reviewed.**

Your agent reads a `.env`. It runs a bare `env` buried in a compound command. It
prints a traceback holding a token. It follows an instruction someone planted in
a README. Each of those is a *probe* here — one small, named leak, with a
clearly-fake canary secret (`sk-canary-<random>`, unique per run) planted in a
throwaway sandbox.

```bash
git clone https://github.com/calasdan-sketch/keycanary && cd keycanary     # not on PyPI yet
python -m keycanary                              # score an unprotected setup
python -m keycanary --profile none
python -m keycanary --json
```

The benchmark itself is standard library only. No network. No account. It plants
its own canaries and deletes them. Scoring a profile needs that profile's tool:
`none` and `claude-env-deny` need nothing extra; `stuntkey-hook` and
`stuntkey-full` need the `stuntkey` package; `detect-secrets` needs the
`detect-secrets` command (`pipx install detect-secrets`). If a profile's tool is
missing the run prints `NOT SCORED`, no score, and exits non-zero.

## Why this exists

Some tools in this space do publish a number, and credit where it is due:

- [phantom-secrets](https://github.com/ashlrai/phantom-secrets) publishes
  210 of 450 in-boundary attacks exposing a canary on a plain `.env`, and
  0 of 450 after `phantom init`, with a reproducible harness and a stated
  method and limits.
- [fidelius / accio](https://fidelius.blisslabs.dev/) published 202 live agent
  runs with every transcript public, a named gaps list, and labels its own
  masking "Best Effort".
- Anthropic's [`sandbox.credentials`](https://code.claude.com/docs/en/sandboxing)
  publishes no leak rate, but documents its gaps at length.

Those harnesses are built around the tool that published them (phantom-secrets
publishes one for its own tool). This one takes profiles for any tool: a fixed
set of leaks, a fixed scoring rule, and an adapter system so two protections can
be put on the same rows, including by people who do not trust, or do not use, the
tool that happens to have written the benchmark. Whether that makes it a fairer
yardstick is for others to judge; the probes were shaped by one author with one
tool in mind (see Limits).

We searched for a published leakage measurement from 1Password, Doppler,
Infisical, Vault, LiteLLM and Portkey and found none as of 2026-11-19. Tell us if
that is wrong and we will correct it.

## Outcomes

| status  | meaning |
|---------|---------|
| blocked | the profile denied the tool call before it ran |
| masked  | the call ran, but the canary is gone from what the model would see |
| leaked  | the canary appears in agent-visible output — **a gap** |
| n/a     | the call could not reproduce here (tool missing, daemon down, nothing to leak) |

`n/a` is neither a pass nor a fail, and is reported separately so a profile
cannot improve its score by failing to run.

## Scores

The headline leak score counts **62 leak probes**. Two more probes (`runaway-loop-no-cap`,
`unbounded-retry`) test *cost control* (a spending cap), not key leakage; they are
reported in a separate "cost control" section and are not in the leak score. That
split exists because those two only a spending-cap feature can change, and the
probe set was written by the author of a tool that has one.

The current numbers are in the profile table under "Scoring your own tool". An older table that stood here (stuntkey-hook 44 / 12 / 5) was from before a scoring review on 2026-11-02 found its attribution wrong; it was removed rather than left to be quoted.

## Scoring your own tool

A profile is a small adapter: given a simulated agent tool call, say whether
your protection would have blocked it, and what the agent would have seen if it
ran. See `keycanary/profiles.py` — each loader is a few dozen lines, and
third-party tools are imported lazily, so scoring one never requires installing
another.

**Pull requests adding a profile for your own tool are welcome, including ones
that beat the profiles already here.** A benchmark whose author always wins is
not a benchmark.

Profiles included, scored 2026-11-19 on Windows (`python -m keycanary --profile <name> [--canary opaque]`; 64 probes: 62 leak probes in
the score below, plus 2 cost-control probes shown after the table). A probe that cannot run on this machine under `none` is `n/a` for every
profile. **The author of this benchmark also wrote stuntkey, so read its rows as a claim to re-run, not a result to trust.**

**No real rival guard that covers the shell is scored yet.** The two rows marked "baseline" are configurations the author modelled
from documentation; they are not competing products and not evidence about any vendor.

| Profile | What it models | Leaked (default key) | Leaked (`--canary opaque`) | Extra package needed |
|---|---|---|---|---|
| `none` | nothing | 55 | 53 | none |
| `claude-env-deny` | **Baseline configuration modelled by the author, not a competing product.** Claude Code's documented `deny Read(./.env)` + `Read(./.env.*)` rules, from the docs: file tools only, so every shell route still leaks. It also blocks `.env.example`. | 51 | 49 | none |
| `detect-secrets` | **Baseline configuration modelled by the author, not a competing product.** Yelp's scanner wired as a pre-call and post-output hook; it has no official agent integration. It does not recognise the default `sk-canary-` format, so its score comes from other planted secrets in the same output. Varies run to run (the random sandbox path and key change what its entropy rules flag; `--seed` fixes only the key and did not make it stable): min / median / max over 10 runs. | 17 / 21 / 32 | 17 / 19 / 24 | `detect-secrets` CLI |
| `stuntkey-hook` | stuntkey's Claude Code hook | 0 | 0 | `stuntkey` |
| `stuntkey-full` | the hook plus spending caps | 0 | 0 | `stuntkey` |

Cost control (not in the leak score; `none`, `claude-env-deny`, `detect-secrets` and `stuntkey-hook` let both runaway-spend probes proceed, `stuntkey-full`'s
cap stops both): shown in every run under "COST CONTROL".

The `stuntkey-*` rows were run against a local checkout of stuntkey, not a pinned release. `read-stuntkey-store` keeps its id for stability but tests
"the protection tool's own key store" (the path it reads is stuntkey's `~/.stuntkey/keys.json`; a profile for another tool would want its own path). A test
(`tests/test_scoring_rules.py`) re-runs `none` and `claude-env-deny` and fails if their README numbers are stale.

Not scored, and why: `ggshield` (needs an account), `gitleaks` and `trufflehog` (not run), 1Password, Doppler and Infisical (they publish
no leak measurement and have no profile here yet). `--canary opaque` plants a key with no recognisable format, to show how much of a
tool's score comes from recognising the key rather than keeping it away. A profile's modelling is written in `profiles.py` and pinned by
`tests/test_rival_profiles.py`; a pull request that models a tool more faithfully is welcome.

Profiles that would be useful and do not exist yet:

- `claude-code-sandbox-mask` — Anthropic's built-in `sandbox.credentials`
  masking. Documented as covering shell commands only, not file tools, MCP
  servers or hooks, and **not available on native Windows**. Worth measuring
  rather than taking from the docs.
- `infisical-agent-vault`, `mcp-warden`, `1password-op-run`, and the LLM
  gateways that offer spend caps.

## Honesty rules this benchmark holds itself to

1. **Gaps are printed, not hidden.** Every run lists the probes that leaked, by
   name, in the default output.
2. **Probe count is pinned.** `tests/test_probe_count.py` fails if the number of probes changes without the test (and this README) changing too, so deleting a probe cannot quietly improve a score.
3. **`n/a` is never counted as a pass.**
4. **The scores above were produced by the commands above**, on the platform
   stated, and nothing else.

## Limits

This benchmark does not measure over-blocking: a profile that denies every call would score no leaks here. stuntkey's own `leakbench` adds 20 harmless commands for that; this repo does not have them, so a high score here says nothing about how often a tool breaks legitimate work. Most probes and the profile adapters were written alongside stuntkey and are shaped by one author's view of the problem. It also does not exercise a real model or the real apps, and this repo is not a security guarantee for any tool.

These are simulated tool calls against a pretend filesystem and a pretend
server. They do not exercise a live network layer, a real model, or a real
agent harness, and they cannot show that nothing else can go wrong. A profile
that scores well here has passed 64 specific, public checks — no more than that.

MIT. Built by [Calas Automations Inc.](https://calasautomations.com) alongside
[stuntkey](https://github.com/calasdan-sketch/stuntkey), which is one of the
profiles it scores and does not win every row.
