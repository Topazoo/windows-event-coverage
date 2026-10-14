"""Bounded, explicitly noncausal correlation of normalized events and incident times."""
from __future__ import annotations

import bisect
from collections import Counter
from decimal import Decimal, InvalidOperation

from .common import EvidenceError, envelope, issue, timestamp_ticks, utc_text


def seconds_ticks(value):
    try:
        seconds = Decimal(str(value))
        ticks = seconds * 10_000_000
        if not seconds.is_finite() or seconds < 0 or seconds > 86400 or ticks != ticks.to_integral_value():
            raise EvidenceError("Window must be 0..86400 seconds at <=100ns precision")
        return int(ticks)
    except (InvalidOperation, ValueError) as exc:
        raise EvidenceError("Invalid correlation window") from exc


def correlate(event_result, incidents, *, before_seconds=1800, after_seconds=1800,
              providers=None, event_ids=None, max_pairs=100000):
    if not isinstance(event_result, dict) or type(event_result.get("schema_version")) is not int or event_result["schema_version"] != 1 or event_result.get("kind") != "events" or not isinstance(event_result.get("records"), list):
        raise EvidenceError("Expected normalized events envelope v1")
    if not isinstance(incidents, list) or len(incidents) > 10000 or len(event_result["records"]) > 100000:
        raise EvidenceError("Invalid/oversized incident or event array")
    if type(max_pairs) is not int or not 1 <= max_pairs <= 1_000_000:
        raise EvidenceError("max_pairs must be 1..1000000")
    before, after = seconds_ticks(before_seconds), seconds_ticks(after_seconds)
    issues, prepared = [], []
    if event_result.get("status") != "complete" or event_result.get("issues") or event_result.get("rejected"):
        issues.append(issue("source_event_coverage_partial"))
    for index, event in enumerate(event_result["records"]):
        if not isinstance(event, dict):
            raise EvidenceError("Malformed normalized event")
        ticks = timestamp_ticks(event.get("time_utc"))
        if not isinstance(event.get("channel"), str) or not event["channel"] or type(event.get("event_id")) is not int or not 0 <= event["event_id"] <= 65535:
            raise EvidenceError("Malformed normalized event metadata")
        if event.get("provider") is not None and not isinstance(event["provider"], str):
            raise EvidenceError("Malformed normalized event provider")
        if providers is not None and event.get("provider") not in providers:
            continue
        if event_ids is not None and event["event_id"] not in event_ids:
            continue
        prepared.append((ticks, index, event))
    prepared.sort(key=lambda item: (item[0], item[1]))
    times = [item[0] for item in prepared]
    anchors, ids = [], set()
    for index, anchor in enumerate(incidents):
        if not isinstance(anchor, dict) or not isinstance(anchor.get("id"), str) or not anchor["id"] or anchor["id"] in ids:
            raise EvidenceError("Incidents require distinct nonempty string IDs")
        ids.add(anchor["id"])
        ticks = timestamp_ticks(anchor.get("time_utc"))
        lo = bisect.bisect_left(times, ticks - before)
        hi = bisect.bisect_right(times, ticks + after)
        anchors.append((anchor, ticks, lo, hi))
    if sum(hi - lo for _, _, lo, hi in anchors) > max_pairs:
        raise EvidenceError("Correlation pair cap exceeded; no truncated-success report")
    records = []
    for anchor, ticks, lo, hi in anchors:
        for event_ticks, event_index, event in prepared[lo:hi]:
            delta = event_ticks - ticks
            records.append({"incident_id": anchor["id"], "incident_time_utc": utc_text(anchor["time_utc"]),
                            "event_index": event_index, "event_source_id": event.get("source_id"),
                            "event_source_index": event.get("source_index"),
                            "channel": event["channel"], "record_id": event.get("record_id"),
                            "provider": event.get("provider"), "event_id": event["event_id"],
                            "event_time_utc": event["time_utc"], "delta_100ns": delta,
                            "phase": "before" if delta < 0 else "at" if delta == 0 else "after"})
    counts = Counter((e[2]["channel"], e[2].get("provider"), e[2]["event_id"]) for e in prepared)
    clusters = [{"channel": channel, "provider": provider, "event_id": event_id, "event_records": count}
                for (channel, provider, event_id), count in sorted(counts.items(), key=lambda item: repr(item[0]))]
    return envelope("correlation", records, issues,
                    selection={"before_100ns": before, "after_100ns": after,
                               "providers": providers, "event_ids": event_ids},
                    summary={"selected_event_records": len(prepared), "incidents": len(incidents),
                             "pairs": len(records), "clusters": clusters},
                    interpretation="Temporal association only, not causation. Counts are records, not independent failures; delayed reporting and clock changes remain possible.")


def markdown_report(result):
    if result.get("kind") != "correlation":
        raise EvidenceError("Markdown report requires correlation output")
    def escape(value):
        # Escape HTML and Markdown syntax; source strings are never rendered as active HTML.
        import html
        text = html.escape(str(value), quote=True).replace("\r", " ").replace("\n", " ")
        return "".join("\\" + c if c in "\\`*_{}[]()#+-.!|" else c for c in text)
    summary = result["summary"]
    lines = ["# Offline event correlation", "", result["interpretation"], "",
             f"Status: {result['status']}. Selected records: {summary['selected_event_records']}. "
             f"Incidents: {summary['incidents']}. Pairs: {summary['pairs']}.", "",
             "| Incident | Event UTC | Channel | Event ID | Delta (100ns) | Phase |",
             "|---|---|---|---:|---:|---|"]
    for row in result["records"]:
        lines.append("| " + " | ".join(escape(row[key]) for key in
                     ("incident_id", "event_time_utc", "channel", "event_id", "delta_100ns", "phase")) + " |")
    if result["issues"]:
        lines.extend(["", "Coverage issues: " + ", ".join(escape(i["code"]) for i in result["issues"])])
    return "\n".join(lines) + "\n"
