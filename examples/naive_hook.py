"""A deliberately naive hook, to show the ``exec:`` adapter end to end.

    python -m keycanary --profile "exec:python examples/naive_hook.py"

It denies shell commands that mention an env file or dump the environment, and
does nothing on PostToolUse. Expect it to stop the obvious probes and miss the
indirect ones; that gap is the point of the benchmark. Replace this file with
your own tool's hook command to score it.
"""

import json
import re
import sys

event = json.load(sys.stdin)
if event.get("hook_event_name") == "PreToolUse":
    text = json.dumps(event.get("tool_input", {}))
    if re.search(r"\.env\b|printenv|\benv\b|environ", text):
        print(json.dumps({"hookSpecificOutput": {
            "permissionDecision": "deny",
            "permissionDecisionReason": "naive hook: env access"}}))
