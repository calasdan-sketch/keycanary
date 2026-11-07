"""A deliberately simple output masker, to show what a RANKABLE score looks like.

    python -m keycanary --profile "exec:python examples/literal_masker.py"

It blocks nothing. On PostToolUse it replaces the exact secret it was told about
(the KEYCANARY_CANARY variable) with ***. That stops every probe that prints the
key as-is, and none of the ones that print it base64'd, reversed, spaced out or
upper-cased: the encoded suite exists to show exactly that gap. Replace this file
with your own tool's hook command to score it.
"""

import json
import os
import sys

secret = os.environ.get("KEYCANARY_CANARY", "")
event = json.load(sys.stdin)
if event.get("hook_event_name") == "PostToolUse" and secret:
    resp = event.get("tool_response") or {}
    if isinstance(resp, dict) and any(secret in str(v) for v in resp.values()):
        new = {k: (v.replace(secret, "***") if isinstance(v, str) else v) for k, v in resp.items()}
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                 "updatedToolOutput": new}}))
