"""Protection profiles: given a simulated tool call, decide whether it is
blocked before it runs.

A profile is a callable ``(tool_payload) -> (blocked: bool, reason: str|None)``.
It may also carry three optional attributes, used when present:

``prepare(sbx)``
    called before each probe with the sandbox (plant what the tool would have).
``post(payload, response) -> response``
    the tool ran; return what the model would see. ``response`` is the Bash
    output shape ``{stdout, stderr, interrupted, isImage}``.
``spend(sbx) -> str | None``
    a runaway paid-call loop: the reason it was stopped, or None.

``none`` blocks nothing (the baseline). ``stuntkey-hook`` runs StuntKey's own
Claude Code hook (``stuntkey.hook.check``) twice, as a real install does:
PreToolUse before the call and PostToolUse on its output. ``stuntkey-full`` is
the hook plus StuntKey's spending caps.

Other tools are welcome: add a profile here and send a PR (README: "Adding a
profile").
"""

from __future__ import annotations

import contextlib
import json
import os
from typing import Callable

# (blocked, reason). reason is the profile's own words when it blocks.
Profile = Callable[[dict], "tuple[bool, str | None]"]

BENCH_SERVICE = "keycanary"
BENCH_CAP = 3          # calls_session cap set for the simulated runaway loop
LOOP_TRIES = 50        # how far the simulated loop would get without a cap
_HOME_VARS = ("HOME", "USERPROFILE")


def _profile_none(_payload: dict) -> tuple[bool, str | None]:
    return False, None


@contextlib.contextmanager
def _home(path: str | None):
    """Run the hook as if the sandbox were the user's home (where it looks for
    ~/.stuntkey/fingerprints.json), then put the real values back."""
    if path is None:
        yield
        return
    old = {k: os.environ.get(k) for k in _HOME_VARS}
    os.environ.update({k: path for k in _HOME_VARS})
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _load_stuntkey_hook() -> Profile:
    """Wrap StuntKey's hook. Raises ImportError if StuntKey is not on the path,
    so the harness can mark the profile skipped rather than guess."""
    from stuntkey import hook as hook_mod
    from stuntkey import scrub as scrub_mod

    state: dict = {"home": None}

    def prepare(sbx) -> None:  # type: ignore[no-untyped-def]
        # simulate `stuntkey get`/`add`: the canary is a key StuntKey stores, so
        # its fingerprint is in the (sandbox) fingerprint file, as in real use
        state["home"] = sbx.home
        path = os.path.join(sbx.home, ".stuntkey", scrub_mod.FINGERPRINT_FILE)
        if not os.path.exists(path):
            scrub_mod.remember_key(f"{BENCH_SERVICE}/API_KEY", sbx.canary, path)

    def profile(payload: dict) -> tuple[bool, str | None]:
        stdin_text = json.dumps({"hook_event_name": "PreToolUse", **payload})
        with _home(state["home"]):
            status, out = hook_mod.check(stdin_text)
        if status == 0 and out.strip():
            try:
                spec = json.loads(out)["hookSpecificOutput"]
            except (ValueError, KeyError):
                return False, None
            if spec.get("permissionDecision") == "deny":
                reason = spec.get("permissionDecisionReason", "")
                return True, reason.split(".")[0] if reason else "denied"
        return False, None

    def post(payload: dict, response: dict) -> dict:
        stdin_text = json.dumps({"hook_event_name": "PostToolUse",
                                 **payload, "tool_response": response})
        with _home(state["home"]):
            status, out = hook_mod.check(stdin_text)
        if status != 0 or not out.strip():
            return response
        new = json.loads(out).get("hookSpecificOutput", {}).get("updatedToolOutput")
        # Claude Code ignores a replacement that is not the tool's own shape
        return new if isinstance(new, dict) and set(new) >= set(response) else response

    profile.prepare = prepare  # type: ignore[attr-defined]
    profile.post = post        # type: ignore[attr-defined]
    return profile


def _load_stuntkey_full() -> Profile:
    """The hook plus spending caps. The model: the key lives only in StuntKey,
    so the agent's paid calls go through the broker (`stuntkey proxy`, MCP,
    `call`), which checks caps.begin() before every call. A cap of BENCH_CAP
    calls is set for the run; the loop is stopped if the cap refuses a call."""
    from stuntkey import caps as caps_mod
    from stuntkey.broker import BrokerError

    profile = _load_stuntkey_hook()

    def spend(sbx) -> str | None:  # type: ignore[no-untyped-def]
        home = os.path.join(sbx.home, ".stuntkey")
        os.makedirs(home, exist_ok=True)
        with open(caps_mod.caps_path(home), "w", encoding="utf-8") as f:
            json.dump({BENCH_SERVICE: {"calls_session": BENCH_CAP}}, f)
        for made in range(LOOP_TRIES):
            try:
                caps_mod.begin(home, BENCH_SERVICE, made)
            except BrokerError as e:
                return f"cap stopped call {made + 1}: {str(e).split(',')[0]}"
        return None

    profile.spend = spend  # type: ignore[attr-defined]
    return profile


# ---------------------------------------------------------------------------------------------------------------------
# Other tools. Each profile states how it was MODELLED, because a benchmark that scores a rival by a guess about how it is used
# is only fair if the guess is written down and easy to correct. Send a pull request if a profile misrepresents a tool.
# ---------------------------------------------------------------------------------------------------------------------

_FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "Glob", "Grep"}


def _is_dotenv(name: str) -> bool:
    """The two rules Claude Code's docs recommend, ``Read(./.env)`` and ``Read(./.env.*)``. The second also matches
    ``.env.example``, so this profile over-blocks it (a real cost of that rule, shown by the harmless probes)."""
    base = os.path.basename(name.replace("\\", "/").rstrip("/"))
    return base == ".env" or base.startswith(".env.")


def _profile_claude_env_deny() -> Profile:
    """Claude Code's built-in permission rules ``deny: ["Read(./.env)", "Read(./.env.*)"]``, the setup its own docs recommend for
    keeping secrets out of the agent. MODELLED from the documented behaviour: the rule covers Claude's FILE tools (Read, Edit,
    Glob, Grep) when the path names a .env file. It does NOT cover what a shell command reads (``cat .env``, ``env``,
    ``printenv``): that is the documented limit, so Bash calls pass. No output masking, no scanning of anything else."""
    def profile(payload: dict) -> tuple[bool, str | None]:
        if payload.get("tool_name") not in _FILE_TOOLS:
            return False, None
        ti = payload.get("tool_input") or {}
        for key in ("file_path", "path", "pattern", "notebook_path"):
            v = ti.get(key)
            if isinstance(v, str) and _is_dotenv(v):
                return True, "permission rule denies reading .env files"
        return False, None
    return profile


def _detect_secrets_flags(text: str) -> bool:
    """True when the ``detect-secrets`` command-line tool (Yelp, plugin-based scanner) flags the text. ``scan --string`` runs every
    plugin on one string and prints which ones matched. Raises ImportError if the tool is not installed, so the harness marks the
    profile skipped rather than guess."""
    import shutil
    import subprocess
    exe = shutil.which("detect-secrets")
    if not exe:
        raise ImportError("detect-secrets is not on PATH (pipx install detect-secrets)")
    r = subprocess.run([exe, "scan", "--string", text], capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and "True" in (r.stdout or "")


def _load_detect_secrets() -> Profile:
    """A secret SCANNER used as an agent hook: detect-secrets reads each tool call before it runs (block when it finds a secret in
    the command or its arguments) and each tool's output afterwards (replace it when it finds one). MODELLED: detect-secrets has no
    official agent integration, so this is how a team would plausibly wire a scanner, not a product feature. It only sees what its
    patterns recognise; a command that merely READS a file (``cat .env``) contains no secret, so it passes, and the output is what
    gets scanned. This is the typical limit of any detect-by-pattern approach and is what the benchmark is meant to show."""
    _detect_secrets_flags("probe")      # fail fast (ImportError) when the tool is missing

    def profile(payload: dict) -> tuple[bool, str | None]:
        text = json.dumps(payload.get("tool_input") or {}, ensure_ascii=False)
        if _detect_secrets_flags(text):
            return True, "detect-secrets found a secret in the tool call"
        return False, None

    def post(payload: dict, response: dict) -> dict:
        out = chr(10).join(str(response.get(k) or "") for k in ("stdout", "stderr"))
        if out.strip() and _detect_secrets_flags(out):
            return {**response, "stdout": "[redacted] output withheld: detect-secrets found a secret", "stderr": ""}
        return response

    profile.post = post  # type: ignore[attr-defined]
    return profile


def get(name: str) -> Profile:
    """Return the profile by name, or raise. The stuntkey profiles raise
    ImportError when StuntKey is not importable."""
    if name == "none":
        return _profile_none
    if name == "stuntkey-hook":
        return _load_stuntkey_hook()
    if name == "stuntkey-full":
        return _load_stuntkey_full()
    if name == "claude-env-deny":
        return _profile_claude_env_deny()
    if name == "detect-secrets":
        return _load_detect_secrets()
    raise KeyError(name)


AVAILABLE = ("none", "stuntkey-hook", "stuntkey-full", "claude-env-deny", "detect-secrets")
