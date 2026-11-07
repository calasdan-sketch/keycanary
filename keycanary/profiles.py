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

``none`` blocks nothing (the baseline). ``deny-all`` and ``mask-all`` are
reference cheats that exist to prove the benchmark cannot be gamed: they block
(or blank) everything, so they leak nothing, and fail the benign controls.
``exec:<command>`` scores ANY tool, in any language, that speaks the Claude Code
hook protocol on stdin/stdout (see ``_load_exec``). ``stuntkey-hook`` runs StuntKey's own
Claude Code hook (``stuntkey.hook.check``) twice, as a real install does:
PreToolUse before the call and PostToolUse on its output. ``stuntkey-full`` is
the hook plus StuntKey's spending caps.

Other tools are welcome: add a profile here and send a PR (README: "Scoring
your own tool").
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
from typing import Callable

from . import _proc

# (blocked, reason). reason is the profile's own words when it blocks.
Profile = Callable[[dict], "tuple[bool, str | None]"]

BENCH_SERVICE = "keycanary"
BENCH_CAP = 3          # calls_session cap set for the simulated runaway loop
LOOP_TRIES = 50        # how far the simulated loop would get without a cap
_HOME_VARS = ("HOME", "USERPROFILE")


class ProfileError(RuntimeError):
    """The profile could not be run at all (bad command, crash, garbage output).
    The run is aborted; a broken adapter must never score as "no leaks"."""


def _profile_deny_all(_payload: dict) -> tuple[bool, str | None]:
    return True, "deny-all reference profile"


def _load_mask_all() -> Profile:
    def profile(_payload: dict) -> tuple[bool, str | None]:
        return False, None

    def post(_payload: dict, response: dict) -> dict:
        return {**response, "stdout": "***", "stderr": ""}

    profile.post = post  # type: ignore[attr-defined]
    return profile


EXEC_TIMEOUT = 10  # seconds per hook call
EXEC_MAX_OUTPUT = 1_000_000  # bytes of hook stdout/stderr accepted per call
_EXEC_KEEP = ("PATH", "SYSTEMROOT", "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR",
              "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL")


def _accept_output(new: object, response: dict) -> dict:
    """Claude Code ignores a replacement that does not match the tool's output
    schema and uses the original output (hooks reference, PostToolUse). Same
    here: wrong keys or wrong value types leave the original output in place."""
    if (isinstance(new, dict) and set(new) >= set(response)
            and all(isinstance(new.get(k), str) for k in ("stdout", "stderr"))
            and all(isinstance(new.get(k), bool) for k in ("interrupted", "isImage") if k in response)):
        return new
    return response


def _split_command(command: str) -> list[str]:
    """Split without a shell. On Windows ``shlex(posix=False)`` keeps the quotes
    around "C:\\Program Files\\x.exe"; they are removed so the path launches."""
    argv = shlex.split(command, posix=(os.name != "nt"))
    if os.name == "nt":
        argv = [a[1:-1] if len(a) >= 2 and a[0] == a[-1] and a[0] in "\"'" else a
                for a in argv]
    return argv


def _load_exec(command: str) -> Profile:
    """Score any external tool that implements the Claude Code hook protocol.

    ``command`` is split with shlex (no shell is involved) and run once per
    event. It receives one JSON object on stdin, with the common fields Claude
    Code sends (``session_id``, ``transcript_path``, ``cwd``, ``permission_mode``,
    ``tool_use_id``) plus:

        {"hook_event_name": "PreToolUse",  "tool_name": ..., "tool_input": {...}}
        {"hook_event_name": "PostToolUse", "tool_name": ..., "tool_input": {...},
         "tool_response": {"stdout", "stderr", "interrupted", "isImage"}}

    It blocks a call by exiting 2, or by printing
    ``{"hookSpecificOutput": {"permissionDecision": "deny"}}`` (the deprecated
    top-level ``{"decision": "block"}`` is honoured as deny, as Claude Code does).
    ``ask`` and ``defer`` hand the decision to a person, so they are NOT counted
    as blocked; the result says so. For PostToolUse it replaces the output by
    printing ``{"hookSpecificOutput": {"updatedToolOutput": {...same shape...}}}``.
    Any other exit code, a timeout, oversize output or unparseable stdout aborts
    the run with ProfileError rather than scoring as a pass. (Claude Code itself
    treats those as non-blocking and lets the call run; aborting is the strict,
    fail-closed choice for a benchmark.)

    The hook runs with a minimal environment: HOME and USERPROFILE point at the
    sandbox, KEYCANARY_CANARY holds this run's canary so a tool that must be
    told the secret (to fingerprint it) can be, and CLAUDE_PROJECT_DIR is the
    sandbox, as Claude Code exports it.
    """
    try:
        argv = _split_command(command)
    except ValueError as exc:
        raise ProfileError(f"cannot parse exec command: {exc}") from exc
    if not argv:
        raise ProfileError("exec: needs a command, e.g. exec:'my-hook --flag'")
    state: dict = {"env": None, "sbx": None, "n": 0}

    def prepare(sbx) -> None:  # type: ignore[no-untyped-def]
        env = {k: os.environ[k] for k in _EXEC_KEEP if k in os.environ}
        env.update(HOME=sbx.home, USERPROFILE=sbx.home, KEYCANARY_CANARY=sbx.canary,
                   KEYCANARY_SANDBOX=sbx.home, CLAUDE_PROJECT_DIR=sbx.home)
        state["env"] = env
        state["sbx"] = sbx
        profile.asked = None  # type: ignore[attr-defined]

    def common() -> dict:
        state["n"] += 1
        home = state["sbx"].home if state["sbx"] else ""
        return {"session_id": "keycanary", "cwd": home, "permission_mode": "default",
                "transcript_path": f"{home}/.keycanary-transcript.jsonl",
                "tool_use_id": f"toolu_keycanary_{state['n']:04d}"}

    def call(event: dict) -> dict | None:
        try:
            done = _proc.run(argv, input_text=json.dumps({**common(), **event}),
                             timeout=EXEC_TIMEOUT, env=state["env"], cap=EXEC_MAX_OUTPUT)
        except FileNotFoundError as exc:
            raise ProfileError(f"exec command not found: {argv[0]}") from exc
        except OSError as exc:
            raise ProfileError(f"exec command failed: {type(exc).__name__}") from exc
        if done.timed_out:
            raise ProfileError(f"exec command failed: timed out after {EXEC_TIMEOUT}s")
        if done.truncated:
            raise ProfileError("exec command printed more than "
                               f"{EXEC_MAX_OUTPUT} bytes; refusing to score it")
        if done.returncode == 2:
            return {"_exit2": (done.stderr or done.stdout or "denied").strip()}
        if done.returncode != 0:
            raise ProfileError(f"exec command exited {done.returncode}: "
                               f"{(done.stderr or '').strip()[:120]}")
        if not done.stdout.strip():
            return None
        try:
            data = json.loads(done.stdout)
        except (ValueError, RecursionError) as exc:
            raise ProfileError("exec command printed non-JSON on stdout") from exc
        if not isinstance(data, dict):
            raise ProfileError("exec command printed JSON that is not an object")
        return data

    def profile(payload: dict) -> tuple[bool, str | None]:
        out = call({"hook_event_name": "PreToolUse", **payload})
        if out is None:
            return False, None
        if "_exit2" in out:
            return True, out["_exit2"].splitlines()[0][:120] if out["_exit2"] else "denied"
        spec = out.get("hookSpecificOutput")
        decision, reason = None, None
        if isinstance(spec, dict) and "permissionDecision" in spec:
            decision, reason = spec.get("permissionDecision"), spec.get("permissionDecisionReason")
        elif out.get("decision") in ("block", "approve"):  # deprecated PreToolUse form
            decision, reason = ("deny" if out["decision"] == "block" else "allow"), out.get("reason")
        if decision == "deny":
            return True, str(reason or "denied")[:120]
        if decision in ("ask", "defer"):
            profile.asked = str(reason or decision)[:80]  # type: ignore[attr-defined]
        return False, None

    def post(payload: dict, response: dict) -> dict:
        out = call({"hook_event_name": "PostToolUse", **payload, "tool_response": response})
        if out is None or "_exit2" in out:
            return response
        spec = out.get("hookSpecificOutput")
        new = spec.get("updatedToolOutput") if isinstance(spec, dict) else None
        return _accept_output(new, response)

    profile.prepare = prepare  # type: ignore[attr-defined]
    profile.post = post        # type: ignore[attr-defined]
    profile.asked = None       # type: ignore[attr-defined]
    return profile


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
        return _accept_output(new, response)

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


def get(name: str) -> Profile:
    """Return the profile by name, or raise KeyError for an unknown name. The
    stuntkey profiles raise ImportError when StuntKey is not importable, and
    ``exec:`` raises ProfileError for an unusable command."""
    if name == "none":
        return _profile_none
    if name == "deny-all":
        return _profile_deny_all
    if name == "mask-all":
        return _load_mask_all()
    if name == "stuntkey-hook":
        return _load_stuntkey_hook()
    if name == "stuntkey-full":
        return _load_stuntkey_full()
    if name.startswith("exec:"):
        return _load_exec(name[len("exec:"):])
    raise KeyError(name)


AVAILABLE = ("none", "deny-all", "mask-all", "stuntkey-hook", "stuntkey-full", "exec:<command>")
