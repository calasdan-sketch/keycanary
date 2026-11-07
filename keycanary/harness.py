"""Tie the pieces together: build a sandbox, run every probe under a profile."""

from __future__ import annotations

from . import profiles, sandbox
from .loader import Probe, load
from .runner import Result, run_probe


def run(profile_name: str, probes: list[Probe] | None = None) -> list[Result]:
    """Run all probes once under ``profile_name`` in a fresh sandbox.

    Raises KeyError for an unknown profile, ImportError when ``stuntkey-hook`` is
    requested but StuntKey is not importable, and ProfileError when an ``exec:``
    adapter cannot be run."""
    probe_list = probes if probes is not None else load()
    profile = profiles.get(profile_name)
    sbx = sandbox.build()
    try:
        return [run_probe(p, sbx, profile, profile_name) for p in probe_list]
    finally:
        sandbox.destroy(sbx)


def run_repeated(profile_name: str, repeat: int,
                 probes: list[Probe] | None = None) -> tuple[list[Result], list[str]]:
    """Run the suite ``repeat`` times, each in a fresh sandbox with a fresh
    random canary. Returns the last run plus the ids of probes whose status
    differed between runs (``unstable``): a probe whose verdict depends on the
    canary value, timing or host state is not a measurement."""
    if repeat < 1:
        raise ValueError("repeat must be >= 1")
    first = run(profile_name, probes)
    seen = {r.probe_id: {r.status} for r in first}
    last = first
    for _ in range(repeat - 1):
        last = run(profile_name, probes)
        for r in last:
            seen[r.probe_id].add(r.status)
    return last, sorted(i for i, s in seen.items() if len(s) > 1)
