# leakbench

**A vendor-neutral benchmark of 61 ways an AI coding agent can leak an API key.**

Your agent reads a `.env`. It runs a bare `env` buried in a compound command. It
prints a traceback holding a token. It follows an instruction someone planted in
a README. Each of those is a *probe* here — one small, named leak, with a
clearly-fake canary secret (`sk-canary-<random>`, unique per run) planted in a
throwaway sandbox.

```bash
pipx run leakbench                      # score an unprotected setup
pipx run leakbench --profile none
pipx run leakbench --json
```

No dependencies. No network. No account. It plants its own canaries and deletes
them.

## Why this exists

Every tool in this space says the agent never sees your key. None of them
publish a number, and none of them publish what they *miss*. "Secretless" is an
architecture claim, and an architecture claim you cannot run is a brochure.

So: a fixed set of leaks, a fixed scoring rule, and a profile system so any tool
can be scored on the same probes — including by people who do not trust, or do
not use, the tool that happens to have written the benchmark.

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

All five are the same shape: a program *you* wrote, run by the agent, printing
its own environment. A tool-call hook cannot see inside a subprocess it did not
inspect. That is a real limit, not an oversight, and no amount of pattern
matching closes it.

## Scoring your own tool

A profile is a small adapter: given a simulated agent tool call, say whether
your protection would have blocked it, and what the agent would have seen if it
ran. See `leakbench/profiles.py` — each loader is a few dozen lines, and
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
