"""Regenerate bench/results.json: the numbers the README table quotes.

    python bench/run.py            # write bench/results.json and print the table
    python bench/run.py --check    # exit 1 if bench/results.json no longer matches a fresh run

Only profiles that need nothing installed are measured (the stuntkey profiles
need StuntKey importable and are listed in the README as measured separately).
Numbers depend on the platform: probes whose tool is missing are n/a.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from keycanary import __version__, harness, loader, report  # noqa: E402

OUT = os.path.join(ROOT, "bench", "results.json")
PY = sys.executable
PROFILES = {
    "none": "none",
    "deny-all": "deny-all",
    "mask-all": "mask-all",
    "exec: naive regex hook": f"exec:{PY} {os.path.join(ROOT, 'examples', 'naive_hook.py')}",
    "exec: literal masker": f"exec:{PY} {os.path.join(ROOT, 'examples', 'literal_masker.py')}",
}


def measure() -> dict:
    probes = loader.load()
    rows = {}
    for label, spec in PROFILES.items():
        t = time.perf_counter()
        results = harness.run(spec, probes)
        secs = time.perf_counter() - t
        core = [r for r in results if r.suite == "core"]
        enc = [r for r in results if r.suite == "encoded"]
        ctl = report.control_summary(results)
        rows[label] = {
            "core": report.summary(core),
            "encoded_leaked": sum(r.status == "leaked" for r in enc),
            "encoded_total": len(enc),
            "controls": ctl,
            "rankable": report.metrics(results)["rankable"],
            "seconds": round(secs, 1),
        }
    return {"keycanary": __version__, "probe_set_sha256": loader.probe_set_hash(probes),
            "suites": loader.EXPECTED, "platform": sys.platform,
            "python": platform.python_version(), "profiles": rows}


def comparable(d: dict) -> dict:
    """Everything except wall-clock time and the interpreter patch version."""
    out = json.loads(json.dumps(d))
    out.pop("python", None)
    for row in out["profiles"].values():
        row.pop("seconds", None)
    return out


def main() -> int:
    fresh = measure()
    if "--check" in sys.argv:
        with open(OUT, encoding="utf-8") as fh:
            saved = json.load(fh)
        if comparable(saved) != comparable(fresh):
            print("bench/results.json is stale; run: python bench/run.py", file=sys.stderr)
            return 1
        print("bench/results.json matches a fresh run")
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(fresh, fh, indent=2)
        fh.write("\n")
    for label, row in fresh["profiles"].items():
        c = row["core"]
        print(f"{label:28} core {c['blocked']}/{c['masked']}/{c['leaked']}/{c['n/a']}  "
              f"encoded leaked {row['encoded_leaked']}/{row['encoded_total']}  "
              f"controls ok {row['controls']['ok']}  rankable {row['rankable']}  {row['seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
