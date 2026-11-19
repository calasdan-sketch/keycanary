"""Tie the pieces together: build a sandbox, run every probe under a profile."""

from __future__ import annotations

from . import profiles, sandbox
from .loader import Probe, load
from .runner import Result, run_probe


def run(profile_name: str, probes: list[Probe] | None = None) -> list[Result]:
    """Run all probes once under ``profile_name`` in a fresh sandbox.

    Raises KeyError for an unknown profile and ImportError when
    ``stuntkey-hook`` is requested but StuntKey is not importable.
    """
    probe_list = probes if probes is not None else load()
    profile = profiles.get(profile_name)
    sbx = sandbox.build()
    try:
        results = [run_probe(p, sbx, profile, profile_name) for p in probe_list]
        if profile_name == "none":
            return results
        # a probe that cannot reproduce on this machine under the baseline is n/a
        # for every profile, so no profile gains a "blocked" from a missing tool
        base = {p.id: run_probe(p, sbx, profiles.get("none"), "none").status for p in probe_list}
        return [r if base[r.probe_id] != "n/a" else
                Result(r.probe_id, r.category, r.profile, "n/a", "n/a on the baseline (none) profile here")
                for r in results]
    finally:
        sandbox.destroy(sbx)
