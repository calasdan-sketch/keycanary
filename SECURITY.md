# Security policy

keycanary is a benchmark: it plants fake secrets in a throwaway folder and runs simulated tool calls. It is **not a security tool, and a good score is not a security guarantee** for anything. It has not been independently reviewed.

## Reporting a problem

Report a security problem (for example a probe that could harm a person running it, or a way the sandbox escapes its folder) privately, not in a public issue:

- GitHub private vulnerability reporting: the repository's Security tab, "Report a vulnerability"
- or email security@calasautomations.com

Please include what you ran, the version, and a minimal reproduction. Do not include real credentials. This is a small project with no service-level guarantee; we aim to reply within a few working days.

Wrong scores, unfair profiles and missing tools are not security problems: please open an ordinary issue or a pull request.
