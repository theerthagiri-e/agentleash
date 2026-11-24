"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import rules as R
from .analyzer import analyze_snapshot, severity_at_least
from .report import to_json, to_text


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=["text", "json"], default="text", help="output format")
    parser.add_argument("--fail-on", choices=R.SEVERITIES, default="high",
                        help="exit with status 1 if any finding is at or above this severity (default: high)")
    parser.add_argument("--output", help="write the report to this file instead of stdout")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentleash",
        description="Find AI agents on AWS that hold more permissions than they need.",
    )
    parser.add_argument("--version", action="version", version="agentleash " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="read agents and their roles from AWS, then analyze")
    scan.add_argument("--region", help="AWS region (defaults to the profile's region)")
    scan.add_argument("--profile", help="AWS named profile")
    scan.add_argument("--target", choices=["all", "agentcore", "classic"], default="all",
                      help="what to scan: Bedrock AgentCore, Bedrock Agents Classic, or both (default: all)")
    scan.add_argument("--save-snapshot", help="also write the collected snapshot to this JSON file")
    _add_output_args(scan)

    analyze = sub.add_parser("analyze", help="analyze a previously saved snapshot file (no AWS access)")
    analyze.add_argument("snapshot", help="path to a snapshot JSON file")
    _add_output_args(analyze)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "scan":
            from .collector import collect

            snapshot = collect(args.region, args.profile, args.target)
            if args.save_snapshot:
                with open(args.save_snapshot, "w", encoding="utf-8") as fh:
                    json.dump(snapshot, fh, indent=2, default=str)
        else:
            with open(args.snapshot, encoding="utf-8") as fh:
                snapshot = json.load(fh)
            if not isinstance(snapshot, dict):
                raise ValueError("snapshot file must contain a JSON object")
    except Exception as exc:  # noqa: BLE001 - report any failure as a clean CLI error
        print("agentleash: error: %s" % exc, file=sys.stderr)
        return 2

    findings = analyze_snapshot(snapshot)
    report = to_json(snapshot, findings) if args.format == "json" else to_text(snapshot, findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")

    return 1 if any(severity_at_least(f.severity, args.fail_on) for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
