"""python -m aegis.agent enroll|heartbeat|run"""

from __future__ import annotations

import argparse
import json
import os
import sys

from aegis.agent.client import enroll, heartbeat, identity_paths, run_loop


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.agent",
        description="Thin Aegis host collector. Enrolls with a one-time token and heartbeats with a client certificate.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enroll_p = sub.add_parser("enroll", help="Exchange a one-time token for cert files under ~/.aegis/agent/")
    enroll_p.add_argument("--url", required=True, help="Console URL, e.g. http://127.0.0.1:8000")
    enroll_p.add_argument(
        "--token",
        default=os.getenv("AEGIS_ENROLLMENT_TOKEN", ""),
        help="One-time token from Settings, or AEGIS_ENROLLMENT_TOKEN",
    )
    enroll_p.add_argument(
        "--ca",
        default=os.getenv("AEGIS_SITE_CA", ""),
        help="Site CA PEM used to verify HTTPS (copy of the console ~/.aegis/ca/ca.crt)",
    )

    sub.add_parser("heartbeat", help="Send one signed heartbeat using ~/.aegis/agent/")
    run_p = sub.add_parser("run", help="Heartbeat loop (default every 30s)")
    run_p.add_argument("--interval", type=float, default=30.0)

    args = parser.parse_args(argv)
    try:
        if args.command == "enroll":
            if not args.token.strip():
                print("Pass --token or set AEGIS_ENROLLMENT_TOKEN.", file=sys.stderr)
                return 2
            result = enroll(args.url, args.token.strip(), ca=args.ca.strip() or None)
            paths = identity_paths()
            print(f"Enrolled agent_id={result['agent_id']}")
            print(f"Wrote {paths['cert']}")
            print(f"Wrote {paths['key']} (mode 600)")
            print(f"Wrote {paths['ca']}")
            print("Next: python -m aegis.agent run")
            return 0
        if args.command == "heartbeat":
            result = heartbeat()
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "run":
            run_loop(interval=max(5.0, args.interval))
            return 0
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
