"""Parse allowlisted Report.wer fields from explicit files, without discovery."""
from __future__ import annotations

import re
import uuid

from .common import EvidenceError, decode_text, envelope, issue, read_bytes, source_id, ticks_text

BASE_FIELDS = {"EventType", "EventTime", "ReportIdentifier", "IntegratorReportIdentifier",
               "AppName", "AppVersion", "ApplicationName", "ReportStatus"}
PATH_FIELDS = {"AppPath", "ApplicationPath"}
SIGNATURE = re.compile(r"(?:DynamicSig|Sig)\[(\d{1,4})\]\.(?:Name|Value)$")


def parse_wer_file(path, *, include_signatures=False, include_paths=False):
    raw = read_bytes(path, 1024 * 1024)
    fields, issues = [], []
    for index, line in enumerate(decode_text(raw).splitlines()):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        selected = key in BASE_FIELDS or (include_paths and key in PATH_FIELDS) or (include_signatures and SIGNATURE.fullmatch(key))
        if not selected:
            continue
        if len(value) > 8192:
            raise EvidenceError("Selected WER value exceeds limit")
        fields.append({"name": key, "value": value})
    if not fields:
        raise EvidenceError("No recognized WER fields")
    values = {}
    for field in fields:
        if field["name"] in values:
            issues.append(issue("duplicate_wer_field_preserved"))
        values.setdefault(field["name"], []).append(field["value"])
    ids = []
    for value in values.get("ReportIdentifier", []):
        try:
            ids.append(str(uuid.UUID(value.strip().strip("{}"))))
        except ValueError:
            issues.append(issue("invalid_report_identifier"))
    # IntegratorReportIdentifier is a distinct relationship, not a fallback dedup ID.
    unique = set(ids)
    report_id = next(iter(unique)) if len(unique) == 1 and not any(i["code"] == "invalid_report_identifier" for i in issues) else None
    if len(unique) > 1:
        issues.append(issue("conflicting_report_identifiers"))
    if report_id is None:
        issues.append(issue("missing_unambiguous_report_id_preserved"))
    event_time = None
    times = values.get("EventTime", [])
    if len(times) == 1:
        try:
            if not re.fullmatch(r"[0-9]{1,20}", times[0]):
                raise ValueError()
            event_time = ticks_text(int(times[0]) - 116444736000000000)
        except (ValueError, EvidenceError):
            issues.append(issue("invalid_wer_filetime"))
    elif len(times) > 1:
        issues.append(issue("ambiguous_wer_filetime"))
    record = {"source_id": source_id(raw), "report_id": report_id, "time_utc": event_time,
              "fields": fields}
    return envelope("wer", [record], issues, selection={"signatures_included": include_signatures,
                                                        "paths_included": include_paths})


def parse_wer_files(paths, **options):
    if not paths or len(paths) > 1000:
        raise EvidenceError("Supply 1 to 1000 explicit WER files")
    records, issues, seen, rejected = [], [], {}, 0
    for index, path in enumerate(paths):
        try:
            result = parse_wer_file(path, **options)
        except (EvidenceError, OSError):
            issues.append(issue("invalid_or_unreadable_wer_file", index)); rejected += 1; continue
        issues.extend({**item, "file_index": index} for item in result["issues"])
        record = result["records"][0]
        record["file_index"] = index
        identifier = record["report_id"]
        if identifier:
            # Only byte-identical files with the same valid ID collapse; conflicting reports remain.
            prior = seen.setdefault(identifier, set())
            if record["source_id"] in prior:
                issues.append(issue("exact_report_duplicate_removed", index)); continue
            if prior:
                issues.append(issue("report_id_conflict_preserved", index))
            prior.add(record["source_id"])
        records.append(record)
    return envelope("wer", records, issues, rejected=rejected,
                    selection={"signatures_included": options.get("include_signatures", False),
                               "paths_included": options.get("include_paths", False)})
