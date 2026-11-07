"""Load probe definitions from keycanary/probes/*.json.

Each JSON file holds a list of probes (grouped by category). A probe is a dict:

    id        unique short name
    category  which family of leak
    attack    plain words: what an agent would run or read
    tool      the PreToolUse payload a profile evaluates: {tool_name, tool_input}
    pre       optional list of earlier tool events (e.g. the Write that created a
              script) that the profile also sees, before ``tool`` runs
    run       how to actually test the leak: {kind, cmd}
              kind in: sh | python | node | powershell | cmd | none
    check     canary_in_output (default) | write_tamper | no_guard | control
    expect    control probes only: text that must survive, untouched, in the output

Placeholders ``{SBX}`` (sandbox home) and ``{CANARY}`` are substituted at run
time by the runner, not here.

The probe set is pinned: how many probes each suite must have is fixed in
``EXPECTED``, and :func:`load` raises if a file is added, removed or edited so
the count changes. Deleting a probe therefore cannot quietly improve a score.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

PROBE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probes")

# file stem -> suite. Everything not listed here is the original "core" suite.
_SUITE_BY_FILE = {"encoded": "encoded", "controls": "control"}
SUITES = ("core", "encoded", "control")
# The pinned probe count per suite. Changing a probe file means changing this
# number in the same commit, in plain view of a reviewer.
EXPECTED = {"core": 61, "encoded": 8, "control": 10}
CHECKS = ("canary_in_output", "write_tamper", "no_guard", "control")


class ProbeSetError(ValueError):
    """The probe files do not match the pinned set. Fail closed."""


@dataclass(frozen=True)
class Probe:
    id: str
    category: str
    attack: str
    tool: dict
    run: dict = field(default_factory=dict)
    check: str = "canary_in_output"
    suite: str = "core"
    pre: tuple = ()
    expect: str = ""


def _coerce(raw: dict, suite: str) -> Probe:
    if not isinstance(raw, dict):
        raise ProbeSetError(f"probe is not an object: {raw!r}")
    missing = {"id", "category", "attack", "tool"} - raw.keys()
    if missing:
        raise ProbeSetError(f"probe missing fields {sorted(missing)}: {raw!r}")
    check = raw.get("check", "canary_in_output")
    if check not in CHECKS:
        raise ProbeSetError(f"probe {raw['id']}: unknown check {check!r}")
    if (check == "control") != (suite == "control"):
        raise ProbeSetError(f"probe {raw['id']}: 'control' check belongs only in the control suite")
    if check == "control" and raw.get("run", {}).get("kind") != "none" and not raw.get("expect"):
        raise ProbeSetError(f"probe {raw['id']}: a control that runs needs 'expect'")
    return Probe(
        id=raw["id"], category=raw["category"], attack=raw["attack"],
        tool=raw["tool"], run=raw.get("run", {}), check=check, suite=suite,
        pre=tuple(raw.get("pre", ())), expect=raw.get("expect", ""),
    )


def load(probe_dir: str = PROBE_DIR, *, enforce_pin: bool | None = None) -> list[Probe]:
    """Every probe from every JSON file, sorted by id.

    Raises on a duplicate id, a malformed probe, or (for the bundled probe
    directory) a suite whose size differs from ``EXPECTED``. ``enforce_pin``
    defaults to True only for the bundled directory so tests can load small
    custom sets."""
    if enforce_pin is None:
        enforce_pin = os.path.abspath(probe_dir) == os.path.abspath(PROBE_DIR)
    probes: list[Probe] = []
    seen: set[str] = set()
    for name in sorted(os.listdir(probe_dir)):
        if not name.endswith(".json"):
            continue
        suite = _SUITE_BY_FILE.get(name[:-5], "core")
        with open(os.path.join(probe_dir, name), encoding="utf-8") as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else [data]
        for raw in items:
            probe = _coerce(raw, suite)
            if probe.id in seen:
                raise ProbeSetError(f"duplicate probe id: {probe.id}")
            seen.add(probe.id)
            probes.append(probe)
    if enforce_pin:
        for suite, want in EXPECTED.items():
            got = sum(1 for p in probes if p.suite == suite)
            if got != want:
                raise ProbeSetError(
                    f"suite '{suite}' has {got} probes but the pinned set has {want}")
    return sorted(probes, key=lambda p: p.id)


def probe_set_hash(probes: list[Probe]) -> str:
    """A stable fingerprint of the probe definitions, recorded in every JSON
    report so two scores are only compared when they used the same probes."""
    canon = json.dumps(
        [{"id": p.id, "suite": p.suite, "category": p.category, "tool": p.tool,
          "pre": list(p.pre), "run": p.run, "check": p.check, "expect": p.expect}
         for p in sorted(probes, key=lambda p: p.id)],
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
