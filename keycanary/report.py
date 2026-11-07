"""Render benchmark results: text table, JSON, Markdown, JUnit XML, SARIF.

Scores are computed over the leak probes only. Benign controls are reported
separately, and a run that over-blocks or alters a control is marked NOT
RANKABLE: a profile cannot win by denying or blanking everything.
"""

from __future__ import annotations

import json
import platform
import re
import sys
from collections import Counter
from xml.sax.saxutils import escape, quoteattr

from . import __version__
from .runner import Result

STATUSES = ("blocked", "masked", "leaked", "n/a")
CONTROL_STATUSES = ("ok", "overblocked", "altered", "n/a")
FORMATS = ("table", "json", "markdown", "junit", "sarif")

# Terminal control, bidi override/isolate and zero-width characters. A profile's
# reason string is untrusted text and is printed to a terminal and into CI
# annotations, so none of these may reach the output.
_UNSAFE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\ufffe\uffff]")


def clean(text: object) -> str:
    """Make untrusted text safe to print: newlines collapse to a space and every
    control, bidi or zero-width character becomes ``?``."""
    return _UNSAFE.sub("?", str(text).replace("\r", " ").replace("\n", " ").replace("\t", " "))


def _leak(results: list[Result]) -> list[Result]:
    return [r for r in results if r.suite != "control"]


def _controls(results: list[Result]) -> list[Result]:
    return [r for r in results if r.suite == "control"]


def summary(results: list[Result]) -> dict[str, int]:
    """Counts of blocked/masked/leaked/n-a over the leak probes (not controls)."""
    counts = Counter(r.status for r in _leak(results))
    return {s: counts.get(s, 0) for s in STATUSES}


def control_summary(results: list[Result]) -> dict[str, int]:
    counts = Counter(r.status for r in _controls(results))
    return {s: counts.get(s, 0) for s in CONTROL_STATUSES}


def metrics(results: list[Result]) -> dict:
    s, c = summary(results), control_summary(results)
    applicable = s["blocked"] + s["masked"] + s["leaked"]
    total = sum(s.values())
    stopped = s["blocked"] + s["masked"]
    ran_controls = sum(c.values())
    broken = c["overblocked"] + c["altered"]
    return {
        "applicable": applicable,
        "stopped": stopped,
        "protection_rate": round(stopped / applicable, 4) if applicable else None,
        "coverage": round(applicable / total, 4) if total else None,
        "controls_ok": c["ok"],
        "controls_broken": broken,
        # rankable only when benign controls were run, at least one could be
        # judged, and none were broken
        "rankable": bool(ran_controls) and c["ok"] > 0 and broken == 0,
    }


def meta(probe_hash: str | None = None, repeat: int = 1) -> dict:
    return {"keycanary": __version__, "probe_set_sha256": probe_hash,
            "python": platform.python_version(), "platform": sys.platform,
            "repeat": repeat}


def to_json(results: list[Result], profile: str, *, probe_hash: str | None = None,
            unstable: list[str] | None = None, repeat: int = 1) -> str:
    return json.dumps({
        "profile": profile,
        "total": len(results),
        "summary": summary(results),
        "controls": control_summary(results),
        "metrics": metrics(results),
        "meta": meta(probe_hash, repeat),
        "unstable": unstable or [],
        "results": [{**r.__dict__, "detail": clean(r.detail)} for r in results],
    }, indent=2)


def _col(text: str, width: int) -> str:
    text = text if len(text) <= width else text[: width - 1] + "…"
    return text.ljust(width)


def _headline(results: list[Result]) -> str:
    m, s = metrics(results), summary(results)
    if m["protection_rate"] is None:
        line = "protection: n/a (no probe could be applied)"
    else:
        line = (f"protection: {m['stopped']}/{m['applicable']} applicable leaks stopped "
                f"({m['protection_rate']:.0%}); coverage {m['applicable']}/{sum(s.values())}")
    if _controls(results):
        c = control_summary(results)
        line += f"; benign controls ok {c['ok']}/{sum(c.values())}"
        if not m["rankable"]:
            line += (f"  ** NOT RANKABLE: {m['controls_broken']} benign call(s) "
                     "denied or altered, or no control could be judged **")
    return line


def to_table(results: list[Result], profile: str) -> str:
    lines = [f"keycanary {__version__} — profile: {clean(profile)} — {len(results)} probes", ""]
    lines.append(f"{_col('ID', 28)} {_col('CATEGORY', 20)} {_col('STATUS', 11)} DETAIL")
    lines.append("-" * 100)
    for r in sorted(results, key=lambda x: (x.suite == "control", x.category, x.probe_id)):
        lines.append(f"{_col(clean(r.probe_id), 28)} {_col(clean(r.category), 20)} "
                     f"{_col(r.status, 11)} {clean(r.detail)}")
    s = summary(results)
    lines += ["", "  ".join(f"{k}={v}" for k, v in s.items())]
    if _controls(results):
        lines.append("controls: " + "  ".join(f"{k}={v}" for k, v in control_summary(results).items()))
    lines += [_headline(results)]
    gaps = sorted(clean(r.probe_id) for r in _leak(results) if r.status == "leaked")
    if gaps:
        lines += ["", f"GAPS (leaked, {len(gaps)}): " + ", ".join(gaps)]
    bad = sorted(clean(r.probe_id) for r in _controls(results) if r.status in ("overblocked", "altered"))
    if bad:
        lines += ["", f"BROKEN CONTROLS ({len(bad)}): " + ", ".join(bad)]
    return "\n".join(lines)


def to_markdown(results: list[Result], profile: str) -> str:
    s = summary(results)
    out = [f"### keycanary — `{clean(profile)}`", "",
           "| blocked | masked | leaked | n/a |", "|---|---|---|---|",
           f"| {s['blocked']} | {s['masked']} | **{s['leaked']}** | {s['n/a']} |", "",
           _headline(results), ""]
    gaps = [r for r in sorted(_leak(results), key=lambda x: x.probe_id) if r.status == "leaked"]
    if gaps:
        out += ["<details><summary>Gaps (leaked)</summary>", ""]
        out += [f"- `{clean(r.probe_id)}` ({clean(r.category)}): {clean(r.detail)}" for r in gaps]
        out += ["", "</details>"]
    return "\n".join(out)


def to_junit(results: list[Result], profile: str) -> str:
    """One testcase per probe: leaked / overblocked / altered are failures,
    n/a is skipped. Loads in any CI that reads JUnit XML."""
    bad = ("leaked", "overblocked", "altered")
    fails = sum(1 for r in results if r.status in bad)
    skips = sum(1 for r in results if r.status == "n/a")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuite name={quoteattr("keycanary " + clean(profile))} '
             f'tests="{len(results)}" failures="{fails}" skipped="{skips}">']
    for r in sorted(results, key=lambda x: x.probe_id):
        lines.append(f'  <testcase classname={quoteattr(clean(r.category))} '
                     f'name={quoteattr(clean(r.probe_id))}>')
        if r.status in bad:
            lines.append(f'    <failure message={quoteattr(r.status)}>{escape(clean(r.detail))}</failure>')
        elif r.status == "n/a":
            lines.append(f'    <skipped message={quoteattr(clean(r.detail))}/>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines)


def to_sarif(results: list[Result], profile: str) -> str:
    """SARIF 2.1.0, one result per leaked probe or broken control, so a leak
    shows up in GitHub code scanning like any other finding."""
    bad = [r for r in sorted(results, key=lambda x: x.probe_id)
           if r.status in ("leaked", "overblocked", "altered")]
    rules = [{"id": clean(r.probe_id), "shortDescription": {"text": clean(r.category)}} for r in bad]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "keycanary", "version": __version__, "rules": rules}},
            "results": [{
                "ruleId": clean(r.probe_id), "level": "error",
                "message": {"text": f"[{clean(profile)}] {r.status}: {clean(r.detail)}"},
            } for r in bad],
        }],
    }, indent=2)


def render(fmt: str, results: list[Result], profile: str, **kw) -> str:  # type: ignore[no-untyped-def]
    if fmt == "json":
        return to_json(results, profile, **kw)
    return {"table": to_table, "markdown": to_markdown, "junit": to_junit,
            "sarif": to_sarif}[fmt](results, profile)
