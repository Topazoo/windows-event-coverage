"""Normalize explicitly supplied JSON/CSV/XML event records; no Windows API calls."""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .common import EvidenceError, decode_text, envelope, issue, read_bytes, source_id, strict_json, timestamp_ticks, utc_text

MAX_RECORDS = 100_000


def event_xml(text: str) -> list[dict]:
    # ElementTree does not fetch external entities; forbid DTD/entities including internal expansion.
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise EvidenceError("DTD/entity declarations are not supported")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, RecursionError) as exc:
        raise EvidenceError("Malformed event XML") from exc
    def local(tag):
        return tag.rsplit("}", 1)[-1]
    roots = [root] if local(root.tag) == "Event" else list(root) if local(root.tag) == "Events" else []
    if not roots and local(root.tag) != "Events":
        raise EvidenceError("Expected Event or Events XML root")
    if len(roots) > MAX_RECORDS:
        raise EvidenceError("Event record limit exceeded")
    rows = []
    for node in roots:
        if local(node.tag) != "Event":
            raise EvidenceError("Non-event child in Events XML")
        system = next((c for c in node if local(c.tag) == "System"), None)
        if system is None:
            rows.append({})
            continue
        fields = {local(c.tag): c for c in system}
        if len(fields) != len(system):
            raise EvidenceError("Duplicate System field in event XML")
        provider, created = fields.get("Provider"), fields.get("TimeCreated")
        def value(name):
            item = fields.get(name)
            return item.text if item is not None else None
        data = []
        for container in node:
            if local(container.tag) == "EventData":
                for child in container:
                    if local(child.tag) == "Data":
                        data.append({"name": child.attrib.get("Name"), "value": "".join(child.itertext())})
        rows.append({"Channel": value("Channel"), "RecordId": value("EventRecordID"),
                     "TimeUtc": created.attrib.get("SystemTime") if created is not None else None,
                     "Provider": provider.attrib.get("Name") if provider is not None else None,
                     "Id": value("EventID"), "Level": value("Level"), "Data": data,
                     "UserDataPresent": any(local(c.tag) == "UserData" for c in node)})
    return rows


def integer(value, minimum=0, maximum=2**64 - 1):
    if isinstance(value, bool) or (not isinstance(value, (str, int))):
        raise EvidenceError("Invalid integer field")
    if isinstance(value, str) and not re.fullmatch(r"[0-9]+", value):
        raise EvidenceError("Expected decimal digits")
    try:
        number = int(value)
    except ValueError as exc:
        raise EvidenceError("Invalid integer field") from exc
    if not minimum <= number <= maximum:
        raise EvidenceError("Integer field out of range")
    return number


def normalize_events(rows: list, *, from_utc=None, through_utc=None, include_payload=False,
                     origin="explicit-input", upstream_issues=None) -> dict:
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise EvidenceError("Expected bounded array of event records")
    low = timestamp_ticks(from_utc) if from_utc else None
    high = timestamp_ticks(through_utc) if through_utc else None
    if (low is None) != (high is None) or (low is not None and low >= high):
        raise EvidenceError("Specify both UTC bounds with start before end")
    records, issues, rejected = [], list(upstream_issues or []), 0
    seen = {}
    for index, row in enumerate(rows):
        try:
            if not isinstance(row, dict):
                raise EvidenceError("Invalid row")
            time = utc_text(row.get("TimeUtc"))
            ticks = timestamp_ticks(time)
            if low is not None and not low < ticks <= high:
                issues.append(issue("outside_window", index)); rejected += 1; continue
            if not isinstance(row.get("Channel"), str) or not row["Channel"].strip():
                raise EvidenceError("Missing channel")
            record = {"source_id": origin, "source_index": index, "channel": row["Channel"],
                      "record_id": integer(row["RecordId"], 1) if row.get("RecordId") not in (None, "") else None,
                      "time_utc": time, "provider": row.get("Provider"), "event_id": integer(row.get("Id"), 0, 65535),
                      "level": integer(row["Level"], 0, 255) if row.get("Level") not in (None, "") else None}
            if record["provider"] is not None and not isinstance(record["provider"], str):
                raise EvidenceError("Invalid provider")
            if record["record_id"] is None:
                issues.append(issue("missing_record_id_preserved", index))
            if include_payload:
                if row.get("UserDataPresent"):
                    issues.append(issue("unsupported_userdata_payload_omitted", index))
                data = row.get("Data")
                if data is None and row.get("DataJson"):
                    data = strict_json(row["DataJson"])
                if isinstance(data, dict):
                    data = [{"name": k, "value": v} for k, v in data.items()]
                if data is not None and (not isinstance(data, list) or any(not isinstance(d, dict) or set(d) != {"name", "value"} for d in data)):
                    raise EvidenceError("Invalid event data")
                record["data"] = data or []
                record["message"] = row.get("Message")
                if row.get("XmlTruncated") in (True, "True", "true") or row.get("MessageTruncated") in (True, "True", "true"):
                    issues.append(issue("truncated_source_payload", index))
            # Record IDs can be reused after clear. Never deduplicate merely on ID.
            if record["record_id"] is not None:
                key = (record["channel"], record["record_id"])
                canonical = json.dumps(row, sort_keys=True, ensure_ascii=True)
                if key in seen:
                    if canonical in seen[key]:
                        issues.append(issue("exact_duplicate_removed", index)); continue
                    issues.append(issue("record_id_reuse_or_conflict_preserved", index))
                seen.setdefault(key, set()).add(canonical)
            records.append(record)
        except (EvidenceError, KeyError, TypeError, RecursionError):
            issues.append(issue("invalid_event_record", index)); rejected += 1
    return envelope("events", records, issues, rejected=rejected,
                    selection={"from_exclusive_utc": utc_text(from_utc) if from_utc else None,
                               "through_inclusive_utc": utc_text(through_utc) if through_utc else None,
                               "payload_included": include_payload},
                    coverage_claim="Input records only; retained/live channel completeness is not established")


def parse_event_file(path, **options):
    raw = read_bytes(path, 8 * 1024 * 1024) if Path(path).suffix.lower() == ".xml" else read_bytes(path)
    text = decode_text(raw)
    suffix = Path(path).suffix.lower()
    upstream = []
    if suffix == ".xml":
        rows = event_xml(text)
    elif suffix == ".csv":
        try:
            reader = csv.DictReader(io.StringIO(text), strict=True)
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise EvidenceError("Missing or duplicate CSV headers")
            rows = []
            for row in reader:
                if None in row or len(rows) >= MAX_RECORDS:
                    raise EvidenceError("Malformed/oversized CSV")
                rows.append(row)
        except csv.Error as exc:
            raise EvidenceError("Malformed CSV") from exc
    elif suffix == ".json":
        obj = strict_json(text)
        if isinstance(obj, dict):
            # Published collector run v1; never silently erase its coverage failures.
            if type(obj.get("SchemaVersion")) is not int or obj["SchemaVersion"] != 1 or not isinstance(obj.get("Channels"), list) or "Events" not in obj:
                raise EvidenceError("Unsupported event JSON envelope")
            rows = obj["Events"]
            for channel in obj["Channels"]:
                if not isinstance(channel, dict):
                    raise EvidenceError("Malformed collector coverage")
                if channel.get("Status") != "complete" or channel.get("Gaps"):
                    upstream.append({"code": "upstream_coverage_not_complete", "channel": channel.get("Channel"),
                                     "status": channel.get("Status"), "gaps": channel.get("Gaps", [])})
        else:
            rows = obj
    else:
        raise EvidenceError("Events require .json, .csv or .xml input")
    return normalize_events(rows, origin=source_id(raw), upstream_issues=upstream, **options)
