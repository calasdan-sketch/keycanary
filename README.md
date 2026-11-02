# keycanary

**A vendor-neutral benchmark of 61 ways an AI coding agent can leak an API key.**

Your agent reads a `.env`. It runs a bare `env` buried in a compound command. It
prints a traceback holding a token. It follows an instruction someone planted in
a README. Each of those is a *probe* here — one small, named leak, with a
clearly-fake canary secret (`sk-canary-<random>`, unique per run) planted in a
throwaway sandbox.

```bash
pipx run keycanary                      # score an unprotected setup
pipx run keycanary --profile none
pipx run keycanary --json
```

No dependencies. No network. No account. It plants its own canaries and deletes
them.

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

What none of them publish is a probe set someone else can run. Each measures
its own tool against no protection, which is a vendor grading itself. There is
no shared set of probes on which a third party can score a tool the probe
author does not own, and no way to put two protections on the same rows.

That is the gap this fills: a fixed set of leaks, a fixed scoring rule, and a
profile system so any tool can be scored on the same probes — including by
people who do not trust, or do not use, the tool that happens to have written
the benchmark.

The enterprise secrets managers and LLM gateways — 1Password, Doppler,
Infisical, Vault, LiteLLM, Portkey and the rest — publish no leakage
measurement at all. Their only quantified benchmarks are latency.

## Outcomes

| status  | meaning |
|---------|---------|
| blocked | the profile denied the tool call before it ran |
| masked  | the call ran, but the canary is gone from what the model would see |
| leaked  | the canary appears in agent-visible output — **a gap** |
| n/a     | the call could not reproduce here (tool missing, daemon down, nothing to leak) |

`n/a` is neither a pass nor a fail, and is reported separately so a profile
cannot improve its score by failing to run.

## Current scores

Measured on Windows, Python 3.12. Reproduce with the commands above.

| Profile | blocked | masked | leaked | n/a |
|---|---|---|---|---|
| `none` — no protection at all | 0 | 0 | **54** | 7 |
| `stuntkey-hook` | 44 | 12 | **5** | 0 |

**The 5 that `stuntkey-hook` does not stop, named:**
`node-prints-process-env`, `script-prints-environ`, `script-reads-env-file`,
`runaway-loop-no-cap`, `unbounded-retry`.

> **These scores and this attribution are being re-measured and should not be
> quoted yet.** An adversarial review of this repo (2026-11-02) found the
> explanation previously given here — that all five are a program printing its
> own environment — to be wrong on all five:
>
> - `runaway-loop-no-cap` and `unbounded-retry` are spend probes whose commands
>   are `for i in 1 2 3; do echo call $i; done`. They print no environment at
>   all; they are scored against an optional `spend` attribute on the profile.
> - The other three attach subprocess output to a **Write** tool event, which
>   no real agent emits. Fed the same output as the `Bash` call an agent would
>   actually make, the hook masks the canary.
>
> The same review found the scoring itself gameable — a profile that denies
> every call scores a perfect 61, because nothing here measures over-blocking —
> and found that the probe count is not pinned in code despite the claim below.
> Both are being fixed. Until then, treat every number on this page as
> provisional.

## Scoring your own tool

A profile is a small adapter: given a simulated agent tool call, say whether
your protection would have blocked it, and what the agent would have seen if it
ran. See `keycanary/profiles.py` — each loader is a few dozen lines, and
third-party tools are imported lazily, so scoring one never requires installing
another.

**Pull requests adding a profile for your own tool are welcome, including ones
that beat the profiles already here.** A benchmark whose author always wins is
not a benchmark.

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
2. **Probe count is pinned.** Deleting a probe cannot improve a score.
3. **`n/a` is never counted as a pass.**
4. **The scores above were produced by the commands above**, on the platform
   stated, and nothing else.

## Limits

These are simulated tool calls against a pretend filesystem and a pretend
server. They do not exercise a live network layer, a real model, or a real
agent harness, and they cannot show that nothing else can go wrong. A profile
that scores well here has passed 61 specific, public checks — no more than that.

MIT. Built by [Calas Automations Inc.](https://calasautomations.com) alongside
[stuntkey](https://github.com/calasdan-sketch/stuntkey), which is one of the
profiles it scores and does not win every row.
