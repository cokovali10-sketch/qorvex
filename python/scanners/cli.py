"""CLI entry point for Qorvex scanners."""

import argparse
import json
import sys

from .scanner import (
    scan_all,
    scan_with,
    _registry,
)


def main():
    parser = argparse.ArgumentParser(
        description="Qorvex Code Scanner — analyze projects for security and quality issues",
    )
    parser.add_argument("action", choices=["scan", "list", "run"], help="Action to perform")
    parser.add_argument("path", nargs="?", help="Project path to scan")
    parser.add_argument("--scanner", "-s", help="Scanner name (for 'run' action)")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="json", help="Output format")
    parser.add_argument("--output", "-o", help="Output file path")

    args = parser.parse_args()

    if args.action == "list":
        print("Available scanners:")
        for name in _registry:
            print(f"  - {name}")
        return

    if not args.path:
        parser.error("path is required for scan/run actions")

    if args.action == "scan":
        results = scan_all(args.path)
    elif args.action == "run":
        if not args.scanner:
            parser.error("--scanner is required for 'run' action")
        results = [scan_with(args.scanner, args.path)]
    else:
        parser.error(f"unknown action: {args.action}")

    output = []
    for r in results:
        output.append(r.to_dict())

    json_output = json.dumps(output, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(json_output)
    else:
        print(json_output)

    # Exit with error if any findings of severity high+
    total_high = sum(
        1 for r in results for f in r.findings if f.severity in ("critical", "high")
    )
    sys.exit(1 if total_high > 0 else 0)


if __name__ == "__main__":
    main()