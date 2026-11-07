"""Run a child process with a hard time limit, a hard output cap and a
process-group kill.

``subprocess.run(timeout=...)`` kills only the direct child. A hook or probe
that starts a background process (``sleep 30 &``) leaves that grandchild holding
the output pipes, so ``run`` then blocks until the grandchild exits, far past
the timeout. An endless writer (``yes``) is also unbounded in memory. Both are
how a hostile or merely buggy adapter could hang or exhaust a CI runner, so
every child here runs in its own session/process group, is killed as a group,
and has its output capped.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

DEFAULT_CAP = 4_000_000  # bytes kept per stream; the rest is read and dropped


@dataclass
class Done:
    returncode: int | None  # None when the child was killed for time
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


def _reader(stream, cap: int, sink: list, flag: list) -> None:  # type: ignore[no-untyped-def]
    kept = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            if kept < cap:
                take = chunk[: cap - kept]
                sink.append(take)
                kept += len(take)
                if len(take) < len(chunk):
                    flag.append(True)
            else:
                flag.append(True)  # keep draining so the child never blocks on a full pipe
    except (OSError, ValueError):
        return


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10, check=False)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def run(argv: list[str], *, input_text: str | None = None, cwd: str | None = None,
        env: dict | None = None, timeout: float = 15, cap: int = DEFAULT_CAP) -> Done:
    """Run ``argv`` (no shell). Raises FileNotFoundError / OSError if it cannot
    be started. A timeout is reported in the result, not raised."""
    kw: dict = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kw["start_new_session"] = True
    proc = subprocess.Popen(
        argv, cwd=cwd, env=env, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    out: list[bytes] = []
    err: list[bytes] = []
    over: list[bool] = []
    threads = [threading.Thread(target=_reader, args=(proc.stdout, cap, out, over), daemon=True),
               threading.Thread(target=_reader, args=(proc.stderr, cap, err, over), daemon=True)]
    for t in threads:
        t.start()
    if input_text is not None:
        def feed() -> None:
            try:
                proc.stdin.write(input_text.encode("utf-8", "replace"))  # type: ignore[union-attr]
                proc.stdin.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass
        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
    timed_out = False
    deadline = time.monotonic() + timeout
    while proc.poll() is None:
        if over:  # output cap exceeded: no reason to keep waiting
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break
        time.sleep(0.01)
    # even on a clean exit, a leftover background child must not outlive the call
    _kill_group(proc)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    for t in threads:
        t.join(timeout=5)
    for stream in (proc.stdout, proc.stderr, proc.stdin):
        try:
            if stream:
                stream.close()
        except (OSError, ValueError):
            pass
    dec = lambda parts: b"".join(parts).decode("utf-8", "replace")  # noqa: E731
    return Done(None if timed_out else proc.returncode, dec(out), dec(err),
                timed_out=timed_out, truncated=bool(over))
