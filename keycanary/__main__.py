"""``python -m keycanary --profile none|stuntkey-hook|exec:<cmd> [--format ...]``."""

from __future__ import annotations

import argparse
import json
import sys

from . import harness, profiles, report
from .loader import SUITES, ProbeSetError, load, probe_set_hash

EXIT_OK, EXIT_GATE, EXIT_SETUP = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keycanary",
        description="Score a secret-protection setup against ways an AI coding "
                    "agent can expose an API key.")
    p.add_argument("--profile", default="none",
                   help="none | deny-all | mask-all | stuntkey-hook | stuntkey-full | "
                        "exec:<command> (any tool speaking the Claude Code hook protocol)")
    p.add_argument("--suite", choices=("all",) + SUITES, default="all",
                   help="which probes to run (default: all)")
    p.add_argument("--format", choices=report.FORMATS, default="table")
    p.add_argument("--json", action="store_true", help="shorthand for --format json")
    p.add_argument("--list", action="store_true", help="list the probes and exit")
    p.add_argument("--repeat", type=int, default=1, metavar="N",
                   help="run N times with fresh canaries and report unstable probes")
    g = p.add_argument_group("CI gates (exit 1 when a gate fails)")
    g.add_argument("--max-leaked", type=int, metavar="N",
                   help="fail if more than N probes leak")
    g.add_argument("--fail-on-leak", action="store_true", help="same as --max-leaked 0")
    g.add_argument("--strict", action="store_true",
                   help="also fail on any n/a, any broken benign control, or any unstable probe")
    g.add_argument("--baseline", metavar="FILE",
                   help="a previous --format json report; fail if a probe leaks now that "
                        "did not leak there")
    return p


def _gates(args, results, unstable, probe_hash) -> list[str]:  # type: ignore[no-untyped-def]
    problems: list[str] = []
    s = report.summary(results)
    limit = 0 if args.fail_on_leak and args.max_leaked is None else args.max_leaked
    if limit is not None and s["leaked"] > limit:
        problems.append(f"{s['leaked']} probes leaked (limit {limit})")
    m = report.metrics(results)
    if args.strict:
        if s["n/a"]:
            problems.append(f"{s['n/a']} probes were n/a (strict)")
        if any(r.suite == "control" for r in results) and not m["rankable"]:
            problems.append("benign controls broken or unjudged (strict)")
        if unstable:
            problems.append(f"unstable probes: {', '.join(unstable)}")
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as fh:
            base = json.load(fh)
        base_hash = (base.get("meta") or {}).get("probe_set_sha256")
        if base_hash != probe_hash:
            raise ValueError("baseline was produced with a different probe set; "
                             "re-record it before comparing")
        was = {r["probe_id"]: r["status"] for r in base.get("results", [])}
        new = sorted(r.probe_id for r in results
                     if r.status == "leaked" and was.get(r.probe_id) != "leaked")
        if new:
            problems.append(f"new leaks vs baseline: {', '.join(new)}")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.json:
        args.format = "json"
    if args.repeat < 1 or args.repeat > 50:
        print("--repeat must be between 1 and 50", file=sys.stderr)
        return EXIT_SETUP
    try:
        all_probes = load()
    except (ProbeSetError, OSError, ValueError) as exc:
        print(f"probe set rejected: {report.clean(exc)}", file=sys.stderr)
        return EXIT_SETUP
    probes = [p for p in all_probes if args.suite in ("all", p.suite)]
    phash = probe_set_hash(all_probes)

    if args.list:
        for p in probes:
            print(f"{p.id}\t{p.suite}\t{p.category}\t{report.clean(p.attack)}")
        return EXIT_OK

    try:
        results, unstable = harness.run_repeated(args.profile, args.repeat, probes)
    except KeyError:
        print(f"unknown profile '{report.clean(args.profile)}'. choose from: "
              f"{', '.join(profiles.AVAILABLE)}", file=sys.stderr)
        return EXIT_SETUP
    except ImportError:
        print(f"profile '{report.clean(args.profile)}' unavailable: StuntKey is not "
              f"importable (install it or run from the repo).", file=sys.stderr)
        return EXIT_SETUP
    except profiles.ProfileError as exc:
        print(f"profile could not run: {report.clean(exc)}", file=sys.stderr)
        return EXIT_SETUP

    kw = {"probe_hash": phash, "unstable": unstable, "repeat": args.repeat} \
        if args.format == "json" else {}
    print(report.render(args.format, results, args.profile, **kw))
    if unstable and args.format == "table":
        print(f"\nUNSTABLE across {args.repeat} runs: {', '.join(unstable)}")

    try:
        problems = _gates(args, results, unstable, phash)
    except (OSError, ValueError) as exc:
        print(f"gate error: {report.clean(exc)}", file=sys.stderr)
        return EXIT_SETUP
    for line in problems:
        print(f"GATE FAILED: {line}", file=sys.stderr)
    return EXIT_GATE if problems else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
