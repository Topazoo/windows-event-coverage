"""CLI: inputs are explicit, outputs are exclusive-create; no overwriting evidence."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .common import EvidenceError, decode_text, read_bytes, strict_json
from .debugger import parse_debugger_file
from .events import parse_event_file
from .manifest import validate_manifest
from .minidump import parse_minidump_file
from .report import correlate, markdown_report
from .wer import parse_wer_files


def load_json(path):
    return strict_json(decode_text(read_bytes(path)))


def parser():
    root = argparse.ArgumentParser(description="Offline explicit-input Windows evidence processing")
    subs = root.add_subparsers(dest="command", required=True)
    for name in ("events", "wer", "debugger", "minidump", "manifest", "correlate"):
        cmd = subs.add_parser(name)
        cmd.add_argument("--output", help="New output file; existing files are never overwritten. Default: stdout")
        if name == "wer":
            cmd.add_argument("inputs", nargs="+")
        elif name != "correlate":
            cmd.add_argument("input")
        if name == "events":
            cmd.add_argument("--from-utc"); cmd.add_argument("--through-utc")
            cmd.add_argument("--include-payload", action="store_true")
        if name in ("wer", "minidump"):
            cmd.add_argument("--include-paths", action="store_true")
        if name == "wer":
            cmd.add_argument("--include-signatures", action="store_true")
        if name == "debugger":
            cmd.add_argument("--include-details", action="store_true")
        if name == "manifest":
            cmd.add_argument("--root", required=True)
            cmd.add_argument("--max-bytes", type=int, default=128 * 1024 * 1024)
        if name == "correlate":
            cmd.add_argument("--events", required=True)
            cmd.add_argument("--incidents", required=True)
            cmd.add_argument("--before-seconds", default="1800")
            cmd.add_argument("--after-seconds", default="1800")
            cmd.add_argument("--provider", action="append")
            cmd.add_argument("--event-id", action="append", type=int)
            cmd.add_argument("--max-pairs", type=int, default=100000)
            cmd.add_argument("--format", choices=("json", "markdown"), default="json")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "events":
            result = parse_event_file(args.input, from_utc=args.from_utc, through_utc=args.through_utc, include_payload=args.include_payload)
        elif args.command == "wer":
            result = parse_wer_files(args.inputs, include_paths=args.include_paths, include_signatures=args.include_signatures)
        elif args.command == "debugger":
            result = parse_debugger_file(args.input, include_details=args.include_details)
        elif args.command == "minidump":
            result = parse_minidump_file(args.input, include_paths=args.include_paths)
        elif args.command == "manifest":
            result = validate_manifest(args.input, args.root, max_bytes=args.max_bytes)
        else:
            result = correlate(load_json(args.events), load_json(args.incidents), before_seconds=args.before_seconds,
                               after_seconds=args.after_seconds, providers=args.provider, event_ids=args.event_id, max_pairs=args.max_pairs)
        text = markdown_report(result) if getattr(args, "format", None) == "markdown" else json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output:
            # Explicit exclusive creation: cannot overwrite an input, prior output or checkpoint.
            with Path(args.output).open("x", encoding="utf-8", newline="\n") as output:
                output.write(text)
        else:
            sys.stdout.write(text)
        return 2 if result["status"] != "complete" else 0
    except (EvidenceError, OSError, ValueError, TypeError, RecursionError) as exc:
        # OS exceptions may include private paths; expose a category, not raw OS details.
        message = str(exc) if isinstance(exc, EvidenceError) else type(exc).__name__
        sys.stderr.write("error: " + message + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
