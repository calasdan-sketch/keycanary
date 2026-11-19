"""Render benchmark results as a text table or JSON."""

from __future__ import annotations

import json
from collections import Counter

from .runner import Result

STATUSES = ("blocked", "masked", "leaked", "n/a")


def summary(results: list[Result]) -> dict[str, int]:
    counts = Counter(r.status for r in results)
    return {s: counts.get(s, 0) for s in STATUSES}


COST_CATEGORY = "spend"  # cost-control probes: reported apart, not in the leak score


def split(results: list[Result]) -> tuple[list[Result], list[Result]]:
    """(leak probes, cost-control probes)."""
    return ([r for r in results if r.category != COST_CATEGORY],
            [r for r in results if r.category == COST_CATEGORY])


def to_json(results: list[Result], profile: str) -> str:
    leak, cost = split(results)
    return json.dumps({
        "profile": profile,
        "total": len(results),
        "summary": summary(leak),
        "leak_probes": len(leak),
        "cost_control_summary": summary(cost),
        "cost_control_probes": len(cost),
        "results": [r.__dict__ for r in results],
    }, indent=2)


def _col(text: str, width: int) -> str:
    text = text if len(text) <= width else text[: width - 1] + "…"
    return text.ljust(width)


def to_table(results: list[Result], profile: str) -> str:
    leak, cost = split(results)
    lines = [f"Agent Leak Benchmark — profile: {profile} — {len(leak)} leak probes + {len(cost)} cost-control probes", ""]
    lines.append(f"{_col('ID', 28)} {_col('CATEGORY', 20)} {_col('STATUS', 8)} DETAIL")
    lines.append("-" * 100)
    for r in sorted(leak, key=lambda x: (x.category, x.probe_id)):
        lines.append(f"{_col(r.probe_id, 28)} {_col(r.category, 20)} "
                     f"{_col(r.status, 8)} {r.detail}")
    lines += ["", "LEAK SCORE: " + "  ".join(f"{k}={v}" for k, v in summary(leak).items())]
    gaps = sorted(r.probe_id for r in leak if r.status == "leaked")
    if gaps:
        lines += ["", f"GAPS (leaked, {len(gaps)}): " + ", ".join(gaps)]
    lines += ["", "COST CONTROL (not part of the leak score; only a spending cap changes it):"]
    for r in sorted(cost, key=lambda x: x.probe_id):
        lines.append(f"{_col(r.probe_id, 28)} {_col(r.status, 8)} {r.detail}")
    return "\n".join(lines)
