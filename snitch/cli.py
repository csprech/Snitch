"""Command line entry point."""
import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

from .server import serve


def main():
    parser = argparse.ArgumentParser(prog="snitch")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("serve")
    run.add_argument("--config", required=True)
    run.add_argument("--db", default="./snitch.db")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8787)
    operator = sub.add_parser("operator")
    operator.add_argument("action", choices=["hold", "release", "incidents", "audit"])
    operator.add_argument("--agent", default="*")
    operator.add_argument("--reason", default="Operator hold")
    operator.add_argument("--url", default="http://127.0.0.1:8787")
    args = parser.parse_args()
    if args.command == "serve":
        serve(json.loads(Path(args.config).read_text()), args.db, args.host, args.port)
    else:
        token = os.environ["SNITCH_ADMIN_KEY"]
        endpoint = args.url.rstrip("/") + "/v1/" + args.action
        data = json.dumps({"agent": args.agent, "reason": args.reason}).encode() if args.action in ("hold", "release") else None
        request = urllib.request.Request(endpoint, data, {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                print(json.dumps(json.load(response), indent=2))
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
