"""``python -m keycanary --profile none|stuntkey-hook [--json]``."""

from __future__ import annotations

import argparse
import os
import sys

from . import harness, profiles, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keycanary",
        description="Agent Leak Benchmark: score a secret-protection setup "
                    "against ways an AI coding agent can expose an API key.")
    parser.add_argument("--profile", default="none", choices=profiles.AVAILABLE,
                        help="protection profile to score (default: none)")
    parser.add_argument("--canary", default="prefixed", choices=("prefixed", "opaque"),
                        help="prefixed: the secret looks like an API key (default); opaque: no recognisable format")
    parser.add_argument("--seed", default=None,
                        help="fixed seed for the canary value only; scanner profiles (detect-secrets) still vary run to run")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a table")
    args = parser.parse_args(argv)
    os.environ["KEYCANARY_CANARY"] = args.canary
    if args.seed is not None:
        os.environ["KEYCANARY_SEED"] = args.seed

    try:
        results = harness.run(args.profile)
    except ImportError:
        print(f"NOT SCORED: profile '{args.profile}' unavailable: its tool is not importable/installed "
              f"(stuntkey-*: pip install stuntkey; detect-secrets: pipx install detect-secrets).", file=sys.stderr)
        return 2

    out = (report.to_json(results, args.profile) if args.json
           else report.to_table(results, args.profile))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
