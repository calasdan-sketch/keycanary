"""``python -m keycanary --profile none|stuntkey-hook|exec:<cmd> [--format ...]``."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys

from . import __author__, __version__, harness, profiles, report
from .loader import SUITES, ProbeSetError, load, probe_set_hash

EXIT_OK, EXIT_GATE, EXIT_SETUP = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keycanary",
        description="Score a secret-protection setup against ways an AI coding "
                    "agent can expose an API key.",
        epilog="examples:\n"
               "  keycanary                                   score an unprotected setup\n"
               "  keycanary --profile example-literal-masker  see a rankable score (ships with the package)\n"
               "  keycanary --profile \"exec:./my-hook\" --fail-on-leak   score your own hook, for CI\n"
               "  keycanary --explain read-env                what one probe does\n"
               "exit codes: 0 pass, 1 a gate failed, 2 the setup is broken (the run was not scored)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", default="none",
                   help="none | deny-all | mask-all | stuntkey-hook | stuntkey-full | "
                        "example-naive-hook | example-literal-masker | "
                        "exec:<command> (any tool speaking the Claude Code hook protocol)")
    p.add_argument("--suite", choices=("all",) + SUITES, default="all",
                   help="which probes to run (default: all)")
    p.add_argument("--version", action="version", version=f"keycanary {__version__} ({__author__})")
    p.add_argument("--only", metavar="ID[,ID...]",
                   help="run just these probes (a partial run: marked as such in JSON, and "
                        "not comparable with a full one)")
    p.add_argument("--explain", metavar="ID",
                   help="show what one probe does (the tool call, the command) and exit")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="write the report to FILE instead of stdout")
    p.add_argument("--format", choices=report.FORMATS, default="table")
    p.add_argument("--json", action="store_true", help="shorthand for --format json")
    p.add_argument("--list", action="store_true", help="list the probes and exit")
    p.add_argument("--hook-timeout", type=float, default=profiles.EXEC_TIMEOUT, metavar="SEC",
                   help="seconds an exec: hook may take per call before the run aborts "
                        f"(default {profiles.EXEC_TIMEOUT:g}; raise it for a slow-starting runtime)")
    p.add_argument("--repeat", type=int, default=1, metavar="N",
                   help="run N times with fresh canaries and report unstable probes")
    g = p.add_argument_group("CI gates (exit 1 when a gate fails)")
    g.add_argument("--max-leaked", type=int, metavar="N",
                   help="fail if more than N probes leak")
    g.add_argument("--fail-on-leak", action="store_true", help="same as --max-leaked 0")
    g.add_argument("--min-protection", type=float, metavar="PCT",
                   help="fail if fewer than PCT percent of applicable leak probes are stopped")
    g.add_argument("--strict", action="store_true",
                   help="also fail on any n/a, any broken benign control, or any unstable probe")
    g.add_argument("--baseline", metavar="FILE",
                   help="a previous --format json report; fail if a probe leaks now that "
                        "did not leak there")
    return p


def _explain(p) -> str:  # type: ignore[no-untyped-def]
    lines = [f"{report.clean(p.id)}  [{p.suite} / {report.clean(p.category)}]",
             f"what: {report.clean(p.attack)}", ""]
    for i, ev in enumerate(list(p.pre) + [p.tool]):
        label = "then, the call under test" if ev is p.tool else f"earlier event {i + 1}"
        lines.append(f"{label}: {report.clean(json.dumps(ev))}")
    if p.run.get("cmd"):
        lines.append(f"how it is reproduced ({p.run.get('kind', 'sh')}): "
                     f"{report.clean(p.run['cmd'])}")
    lines.append(f"judged by: {p.check}" + (f", expects {report.clean(p.expect)!r} to survive"
                                           if p.expect else ""))
    lines.append("{SBX} is the throwaway sandbox directory; {CANARY} this run's fake key.")
    return "\n".join(lines)


def _gates(args, results, unstable, probe_hash) -> list[str]:  # type: ignore[no-untyped-def]
    problems: list[str] = []
    s = report.summary(results)
    m = report.metrics(results)
    limit = 0 if args.fail_on_leak and args.max_leaked is None else args.max_leaked
    if limit is not None and s["leaked"] > limit:
        problems.append(f"{s['leaked']} probes leaked (limit {limit})")
    # A leak gate passed by denying or blanking everything is not a pass: the
    # benchmark's own rule is that a score only counts when the controls hold.
    gated = limit is not None or args.min_protection is not None
    if gated and any(r.suite == "control" for r in results) and m["controls_broken"]:
        problems.append(f"{m['controls_broken']} harmless call(s) were denied or altered, so the "
                        "low leak count does not count (see BROKEN CONTROLS)")
    if args.min_protection is not None:
        rate = m["protection_rate"]
        if rate is None or rate * 100 < args.min_protection:
            shown = "n/a" if rate is None else f"{rate:.1%}"
            problems.append(f"protection {shown} is below {args.min_protection:g}%")
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
        if not isinstance(base, dict) or not isinstance(base.get("results"), list):
            raise ValueError("baseline is not a keycanary --format json report")
        base_hash = (base.get("meta") or {}).get("probe_set_sha256") \
            if isinstance(base.get("meta"), dict) else None
        if base_hash != probe_hash:
            raise ValueError("baseline was produced with a different probe set; "
                             "re-record it before comparing")
        try:
            was = {r["probe_id"]: r["status"] for r in base["results"]}
        except (KeyError, TypeError) as exc:
            raise ValueError("baseline results are not in keycanary's format") from exc
        new = sorted(r.probe_id for r in results
                     if r.status == "leaked" and was.get(r.probe_id) != "leaked")
        if new:
            problems.append(f"new leaks vs baseline: {', '.join(new)}")
    return problems


def _safe_streams() -> None:
    """Never die with a traceback because the console cannot show a character
    (a legacy Windows code page, LANG=C): unshowable characters print as ?."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def _terminate(_signum, _frame):  # type: ignore[no-untyped-def]
    raise KeyboardInterrupt  # one clean-up path for Ctrl-C and for a CI "cancel"


def main(argv: list[str] | None = None) -> int:
    _safe_streams()
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, _terminate)
        except ValueError:  # not the main thread (embedded use)
            pass
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("interrupted; nothing was scored", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # `keycanary | head`: the reader went away. Say nothing, and keep Python from
        # complaining again while it flushes stdout at exit.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        return 141


def _main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.json:
        args.format = "json"
    if not 0.5 <= args.hook_timeout <= 300:
        print("--hook-timeout must be between 0.5 and 300", file=sys.stderr)
        return EXIT_SETUP
    profiles.EXEC_TIMEOUT = args.hook_timeout
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

    if args.explain:
        match = [p for p in all_probes if p.id == args.explain]
        if not match:
            print(f"no probe '{report.clean(args.explain)}'; see --list", file=sys.stderr)
            return EXIT_SETUP
        print(_explain(match[0]))
        return EXIT_OK
    partial = args.suite != "all"
    if args.only:
        wanted = [w.strip() for w in args.only.split(",") if w.strip()]
        known = {p.id for p in all_probes}
        unknown = [w for w in wanted if w not in known]
        if unknown or not wanted:
            print(f"unknown probe id(s): {report.clean(', '.join(unknown) or '(none given)')}",
                  file=sys.stderr)
            return EXIT_SETUP
        probes = [p for p in probes if p.id in wanted]
        partial = True

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

    kw = {"probe_hash": phash, "unstable": unstable, "repeat": args.repeat,
          "partial": partial} if args.format == "json" else {}
    text = report.render(args.format, results, args.profile, **kw)
    if unstable and args.format == "table":
        text += f"\n\nUNSTABLE across {args.repeat} runs: {', '.join(unstable)}"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            print(f"cannot write {report.clean(args.output)}: {report.clean(exc)}", file=sys.stderr)
            return EXIT_SETUP
    else:
        print(text)

    try:
        problems = _gates(args, results, unstable, phash)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"gate error: {report.clean(exc)}", file=sys.stderr)
        return EXIT_SETUP
    for line in problems:
        print(f"GATE FAILED: {line}", file=sys.stderr)
    return EXIT_GATE if problems else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
