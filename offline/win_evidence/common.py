"""Bounded input, exact timestamps and common result envelopes."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_TEXT_BYTES = 32 * 1024 * 1024
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})$"
)


class EvidenceError(ValueError):
    """Invalid or unsupported input; never an empty-success substitute."""


def timestamp_ticks(value: str) -> int:
    """100ns ticks since Unix epoch; require an explicit offset, preserve 7 digits."""
    if not isinstance(value, str) or not (m := ISO.fullmatch(value)):
        raise EvidenceError("Timestamp must be ISO 8601 with an explicit offset and <=7 fractional digits")
    day, clock, fraction, offset = m.groups()
    try:
        naive = datetime.strptime(day + "T" + clock, "%Y-%m-%dT%H:%M:%S")
        minutes = 0
        if offset != "Z":
            hours, mins = map(int, offset[1:].split(":"))
            if hours > 14 or mins > 59 or (hours == 14 and mins):
                raise EvidenceError("Timezone offset out of range")
            minutes = (hours * 60 + mins) * (1 if offset[0] == "+" else -1)
        utc = naive.replace(tzinfo=timezone.utc) - timedelta(minutes=minutes)
        delta = utc - EPOCH
        return (delta.days * 86400 + delta.seconds) * 10_000_000 + int((fraction or "").ljust(7, "0"))
    except (ValueError, OverflowError) as exc:
        raise EvidenceError("Invalid timestamp") from exc


def ticks_text(ticks: int) -> str:
    seconds, subsecond = divmod(ticks, 10_000_000)
    try:
        value = EPOCH + timedelta(seconds=seconds)
    except OverflowError as exc:
        raise EvidenceError("Timestamp out of supported calendar range") from exc
    return f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value:%H:%M:%S}.{subsecond:07d}Z"


def utc_text(value: str) -> str:
    return ticks_text(timestamp_ticks(value))


def read_bytes(path: str | Path, limit: int = MAX_TEXT_BYTES) -> bytes:
    """Read only this explicit file; refuse special files and bounded-size overflow."""
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise EvidenceError("Input must be an explicit regular file, not a symlink")
    with p.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise EvidenceError("Input size limit exceeded")
    return data


def decode_text(data: bytes) -> str:
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16")
        return data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise EvidenceError("Expected UTF-8 or BOM-marked UTF-16 text") from exc


def strict_json(text: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError("Duplicate JSON object key")
            result[key] = value
        return result
    def nonfinite(_):
        raise EvidenceError("Nonfinite JSON number")
    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise EvidenceError("Invalid JSON") from exc


def envelope(kind: str, records: list, issues: list, *, rejected: int = 0, **extra) -> dict:
    return {"schema_version": 1, "kind": kind,
            "status": "partial" if issues or rejected else "complete",
            "records": records, "issues": issues, "rejected": rejected, **extra}


def issue(code: str, index: int | None = None) -> dict:
    result = {"code": code}
    if index is not None:
        result["index"] = index
    return result


def source_id(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
