"""Minimal example: an agent calls tools through Snitch, never directly."""
import json
import os
import secrets
import urllib.request

SNITCH_URL = os.getenv("SNITCH_URL", "http://127.0.0.1:8787")


def guarded_action(tool, arguments):
    request = urllib.request.Request(
        SNITCH_URL + "/v1/execute",
        json.dumps({"tool": tool, "arguments": arguments}).encode(),
        {"Authorization": "Bearer " + os.environ["SNITCH_RESEARCHER_KEY"],
         "Content-Type": "application/json",
         "Idempotency-Key": secrets.token_urlsafe(24)},
    )
    with urllib.request.urlopen(request, timeout=35) as response:
        result = json.load(response)
    if result["decision"] != "allow":
        # Do not retry a blocked action through another route.
        raise RuntimeError(f"Snitch {result['decision']}: {result['reason']} (event {result['event_id']})")
    return result["output"]


if __name__ == "__main__":
    print(guarded_action("public_lookup", {"query": "Portland weather"}))
