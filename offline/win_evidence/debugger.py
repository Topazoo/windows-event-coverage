"""Saved WinDbg text only; never invokes a debugger or symbol server."""
from __future__ import annotations

import re

from .common import EvidenceError, decode_text, envelope, issue, read_bytes, source_id, utc_text

MONTHS = {name: f"{i:02d}" for i, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
SESSION = re.compile(
    r"^Debug session time:\s+(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+"
    r"(\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?)\s+(\d{4})\s+"
    r"\(UTC\s*([+-])\s*(\d{1,2}):(\d{2})\)\s*$", re.M)


def parse_debugger_file(path, *, include_details=False):
    raw = read_bytes(path, 8 * 1024 * 1024)
    text = decode_text(raw)
    if "BUGCHECK_CODE:" not in text:
        raise EvidenceError("No supported kernel bugcheck analysis found")
    if len(re.findall(r"^BUGCHECK_CODE:", text, re.M)) != 1 or len(re.findall(r"^Debug session time:", text, re.M)) > 1:
        raise EvidenceError("Provide a single saved analysis per file")
    issues, fields = [], {}
    for key in ("BUGCHECK_CODE", "BUGCHECK_P1", "BUGCHECK_P2", "BUGCHECK_P3", "BUGCHECK_P4",
                "PROCESS_NAME", "SYMBOL_NAME", "MODULE_NAME", "FAILURE_BUCKET_ID"):
        matches = re.findall(r"^" + key + r":[ \t]*([^\r\n]*)", text, re.M)
        if len(matches) > 1:
            raise EvidenceError("Duplicate debugger field")
        fields[key] = matches[0].strip() if matches else None
    def hex_field(key, required=False):
        value = fields[key]
        if value is None or value == "":
            if required:
                raise EvidenceError("Missing bugcheck code")
            issues.append({"code": "missing_bugcheck_parameter", "field": key})
            return None
        normalized = value.removeprefix("0x").removeprefix("0X").replace("`", "")
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", normalized):
            raise EvidenceError("Invalid bugcheck hexadecimal field")
        return "0x" + format(int(normalized, 16), "x")
    record = {"source_id": source_id(raw), "bugcheck": hex_field("BUGCHECK_CODE", True),
              "parameters": [hex_field("BUGCHECK_P" + str(i)) for i in range(1, 5)],
              "time_utc": None}
    time = SESSION.search(text)
    if time:
        month, day, clock, year, sign, hours, minutes = time.groups()
        if month not in MONTHS:
            raise EvidenceError("Unsupported debugger month")
        record["time_utc"] = utc_text(f"{year}-{MONTHS[month]}-{int(day):02d}T{clock}{sign}{int(hours):02d}:{minutes}")
    else:
        issues.append(issue("missing_or_unsupported_debugger_timestamp"))
    wrong = (fields["FAILURE_BUCKET_ID"] or "").upper().startswith("WRONG_SYMBOLS")
    record["symbol_status"] = "unresolved" if wrong else "not_independently_verified"
    for target, key in (("process", "PROCESS_NAME"), ("symbol", "SYMBOL_NAME"),
                        ("module", "MODULE_NAME"), ("bucket", "FAILURE_BUCKET_ID")):
        record[target] = None if wrong else fields[key]
    if wrong:
        issues.append(issue("wrong_symbols_attribution_suppressed"))
    if include_details:
        dump = re.search(r"Loading Dump File \[([^\]\r\n]+)\]", text)
        stack = re.search(r"(?ms)^STACK_TEXT:[ \t]*\r?\n(.*?)(?:\r?\n\s*\r?\n|\Z)", text)
        record["dump_reference"] = dump.group(1) if dump else None
        record["stack_text"] = stack.group(1) if stack else None
    return envelope("debugger", [record], issues,
                    interpretation="Saved analysis metadata, not independently verified debugger attribution")
