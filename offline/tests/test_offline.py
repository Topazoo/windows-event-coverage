"""All evidence below is generated, including the binary minidumps."""
import contextlib
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from win_evidence import cli, common, debugger, events, manifest, minidump, report, wer


def synthetic_event(record_id=1, time="2025-01-01T00:30:00Z", **extra):
    return {"Channel": "Synthetic", "RecordId": record_id, "TimeUtc": time,
            "Provider": "SyntheticProvider", "Id": 1000, "Level": 2, **extra}


def synthetic_dump(name="C:\\Synthetic\\example.dll", *, memory=False, valid_version=True):
    stream_count = 2 if memory else 1
    module_start = 32 + 12 * stream_count
    name_start = module_start + 112
    encoded = name.encode("utf-16-le")
    name_data = struct.pack("<I", len(encoded)) + encoded
    memory_start = name_start + len(name_data)
    header = struct.pack("<IIIIIIQ", 0x504D444D, 0xA793, stream_count, 32, 0, 0, 0)
    directory = struct.pack("<III", 4, 112, module_start)
    if memory:
        directory += struct.pack("<III", 5, 1024 * 1024, memory_start)
    module = bytearray(108)
    struct.pack_into("<QIIII", module, 0, 0x10000000, 4096, 0, 0xDEADBEEF, name_start)
    struct.pack_into("<IIII", module, 24, 0xFEEF04BD if valid_version else 0, 0x10000, (1 << 16) | 2, (3 << 16) | 4)
    return header + directory + struct.pack("<I", 1) + module + name_data + (b"M" * 1024 * 1024 if memory else b"")


class Files(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, (bytes, bytearray)) else value.encode("utf-8"))
        return path

    def json(self, name, value):
        return self.write(name, json.dumps(value))


class TimestampTests(unittest.TestCase):
    def test_100ns_roundtrip(self):
        self.assertEqual(common.utc_text("2025-01-01T00:00:00.1234567Z"), "2025-01-01T00:00:00.1234567Z")

    def test_offsets_include_minutes(self):
        self.assertEqual(common.utc_text("2025-01-01T05:45:00+05:45"), "2025-01-01T00:00:00.0000000Z")
        self.assertEqual(common.utc_text("2024-12-31T20:30:00-03:30"), "2025-01-01T00:00:00.0000000Z")

    def test_pre_epoch(self):
        self.assertEqual(common.ticks_text(-1), "1969-12-31T23:59:59.9999999Z")

    def test_invalid_timestamps(self):
        for value in (None, "2025-01-01", "2025-01-01T00:00:00", "2025-02-30T00:00:00Z",
                      "2025-01-01T00:00:00+14:01", "2025-01-01T00:00:00+01:99",
                      "2025-01-01T00:00:00.12345678Z", "2025-01-01T00:00:60Z"):
            with self.subTest(value=value), self.assertRaises(common.EvidenceError):
                common.timestamp_ticks(value)

    def test_json_duplicate_and_nonfinite(self):
        for value in ('{"a":1,"a":2}', '{"x":NaN}', '[] trailing'):
            with self.assertRaises(common.EvidenceError):
                common.strict_json(value)


class EventTests(Files):
    def test_xml_duplicate_system_fields_rejected(self):
        with self.assertRaises(common.EvidenceError):
            events.event_xml('<Event><System><EventID>1</EventID><EventID>2</EventID></System></Event>')

    def test_userdata_omission_explicit(self):
        row = synthetic_event(UserDataPresent=True)
        result = events.normalize_events([row], include_payload=True)
        self.assertIn("unsupported_userdata_payload_omitted", [x["code"] for x in result["issues"]])

    def test_decimal_ids_only(self):
        for bad in ("1_0", "+1", "1.0", 1.5, True):
            self.assertEqual(events.normalize_events([synthetic_event(bad)])["rejected"], 1)

    def test_unknown_json_schema_fails(self):
        for schema in (True, 2):
            path = self.json("bad.json", {"SchemaVersion": schema, "Channels": [], "Events": []})
            with self.assertRaises(common.EvidenceError):
                events.parse_event_file(path)

    def test_record_cap_and_malformed_csv(self):
        with mock.patch.object(events, "MAX_RECORDS", 1), self.assertRaises(common.EvidenceError):
            events.normalize_events([synthetic_event(), synthetic_event(2)])
        with self.assertRaises(common.EvidenceError):
            events.parse_event_file(self.write("malformed.csv", 'Id,Channel\n1,Synthetic,extra\n'))

    def test_exact_bounds(self):
        times = ["2025-01-01T00:00:00Z", "2025-01-01T00:00:00.0000001Z",
                 "2025-01-01T01:00:00Z", "2025-01-01T01:00:00.0000001Z"]
        result = events.normalize_events([synthetic_event(i + 1, t) for i, t in enumerate(times)],
                                         from_utc=times[0], through_utc=times[2])
        self.assertEqual([r["record_id"] for r in result["records"]], [2, 3])
        self.assertEqual(result["rejected"], 2)

    def test_invalid_bounds(self):
        for kwargs in ({"from_utc": "2025-01-01T00:00:00Z"},
                       {"from_utc": "2025-01-02T00:00:00Z", "through_utc": "2025-01-01T00:00:00Z"}):
            with self.assertRaises(common.EvidenceError):
                events.normalize_events([], **kwargs)

    def test_missing_ids_never_collapse(self):
        result = events.normalize_events([synthetic_event(None), synthetic_event(None)])
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["status"], "partial")

    def test_identical_duplicate_only(self):
        a = synthetic_event()
        b = synthetic_event(Message="Different payload")
        c = synthetic_event(time="2025-01-01T00:31:00Z")
        result = events.normalize_events([a, a, b, c])
        self.assertEqual(len(result["records"]), 3)
        self.assertIn("record_id_reuse_or_conflict_preserved", [x["code"] for x in result["issues"]])

    def test_invalid_rows_are_partial(self):
        result = events.normalize_events([{}, None, synthetic_event(-1), synthetic_event(Id=True), synthetic_event()])
        self.assertEqual(result["rejected"], 4)
        self.assertEqual(len(result["records"]), 1)

    def test_xml_duplicates_and_unnamed_data(self):
        xml = '<Event xmlns="urn:synthetic"><System><Channel>Synthetic</Channel><Provider Name="Example"/><TimeCreated SystemTime="2025-01-01T00:00:00Z"/><EventID>1</EventID></System><EventData><Data Name="x">first</Data><Data Name="x">second</Data><Data>third</Data></EventData></Event>'
        path = self.write("events.xml", xml)
        result = events.parse_event_file(path, include_payload=True)
        self.assertEqual([d["value"] for d in result["records"][0]["data"]], ["first", "second", "third"])
        self.assertIsNone(result["records"][0]["data"][-1]["name"])

    def test_xml_entities_and_invalid_root_rejected(self):
        for text in ('<!DOCTYPE Event [<!ENTITY x "a">]><Event/>', '<Wrong/>', '<Event>'):
            with self.assertRaises(common.EvidenceError):
                events.event_xml(text)

    def test_json_and_csv_inputs(self):
        path = self.json("events.json", [synthetic_event()])
        self.assertEqual(events.parse_event_file(path)["status"], "complete")
        path = self.write("events.csv", "Channel,RecordId,TimeUtc,Provider,Id,Level\nSynthetic,1,2025-01-01T00:00:00Z,Example,1,2\n")
        self.assertEqual(events.parse_event_file(path)["records"][0]["record_id"], 1)

    def test_duplicate_csv_headers_rejected(self):
        path = self.write("events.csv", "Id,Id\n1,2\n")
        with self.assertRaises(common.EvidenceError):
            events.parse_event_file(path)

    def test_collector_coverage_preserved(self):
        path = self.json("run.json", {"SchemaVersion": 1, "Events": [], "Channels": [{"Channel": "Synthetic", "Status": "denied", "Gaps": []}]})
        self.assertEqual(events.parse_event_file(path)["status"], "partial")

    def test_payload_opt_in(self):
        row = synthetic_event(Message="SYNTHETIC_PRIVATE_PAYLOAD", DataJson='{"name":"value"}', MessageTruncated=True)
        clean = events.normalize_events([row])
        self.assertNotIn("SYNTHETIC_PRIVATE_PAYLOAD", json.dumps(clean))
        detailed = events.normalize_events([row], include_payload=True)
        self.assertEqual(detailed["status"], "partial")
        self.assertEqual(detailed["records"][0]["data"], [{"name": "name", "value": "value"}])

    def test_json_duplicate_data_key_rejected(self):
        result = events.normalize_events([synthetic_event(DataJson='{"x":1,"x":2}')], include_payload=True)
        self.assertEqual(result["rejected"], 1)

    def test_utf16_input(self):
        path = self.write("events.json", json.dumps([synthetic_event()]).encode("utf-16"))
        self.assertEqual(events.parse_event_file(path)["status"], "complete")


class WerTests(Files):
    def test_invalid_and_valid_id_is_not_unambiguous(self):
        path = self.report(fields="ReportIdentifier=invalid\n")
        self.assertIsNone(wer.parse_wer_file(path)["records"][0]["report_id"])

    def test_bad_encoding_rejected(self):
        with self.assertRaises(common.EvidenceError):
            wer.parse_wer_file(self.write("bad.wer", b"\xff\xff\xff"))

    def test_duplicate_time_unknown(self):
        result = wer.parse_wer_file(self.report(fields="EventTime=1\nEventTime=2\n"))
        self.assertIsNone(result["records"][0]["time_utc"])

    def report(self, name="a.wer", fields=""):
        return self.write(name, "EventType=APPCRASH\nReportIdentifier={00000000-0000-0000-0000-000000000001}\n" + fields)

    def test_multidigit_signature_and_default_omission(self):
        path = self.report(fields="Sig[12].Name=Example\nSig[12].Value=VALUE\nDynamicSig[20].Value=OTHER\nAppPath=C:\\Synthetic\\app.exe\nCommandLine=NEVER_EXPORT\n")
        basic = json.dumps(wer.parse_wer_file(path))
        self.assertNotIn("VALUE", basic)
        self.assertNotIn("AppPath", basic)
        full = wer.parse_wer_file(path, include_signatures=True, include_paths=True)
        self.assertIn("Sig[12].Value", [f["name"] for f in full["records"][0]["fields"]])
        self.assertNotIn("NEVER_EXPORT", json.dumps(full))

    def test_duplicate_fields_preserved(self):
        path = self.report(fields="AppName=one\nAppName=two\n")
        result = wer.parse_wer_file(path)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len([f for f in result["records"][0]["fields"] if f["name"] == "AppName"]), 2)

    def test_missing_and_conflicting_ids_preserved(self):
        a = self.write("missing.wer", "EventType=APPCRASH\n")
        b = self.report(fields="ReportIdentifier={00000000-0000-0000-0000-000000000002}\n")
        result = wer.parse_wer_files([a, a, b])
        self.assertEqual(len(result["records"]), 3)
        self.assertTrue(all(r["report_id"] is None for r in result["records"]))

    def test_exact_duplicate_and_id_conflict(self):
        a = self.report()
        b = self.report("b.wer", "AppName=changed\n")
        result = wer.parse_wer_files([a, a, b])
        self.assertEqual(len(result["records"]), 2)
        self.assertIn("report_id_conflict_preserved", [x["code"] for x in result["issues"]])

    def test_filetime(self):
        path = self.report(fields="EventTime=116444736000000001\n")
        self.assertEqual(wer.parse_wer_file(path)["records"][0]["time_utc"], "1970-01-01T00:00:00.0000001Z")

    def test_encoding_and_invalid_file(self):
        path = self.write("unicode.wer", "EventType=APPCRASH\nAppName=例\n".encode("utf-16"))
        self.assertEqual(wer.parse_wer_file(path)["records"][0]["fields"][1]["value"], "例")
        self.assertEqual(wer.parse_wer_files([self.root / "absent"])["rejected"], 1)

    def test_value_cap_and_invalid_id(self):
        with self.assertRaises(common.EvidenceError):
            wer.parse_wer_file(self.report(fields="AppName=" + "x" * 8193))
        path = self.write("invalid.wer", "ReportIdentifier=not-an-id\nEventTime=abc\n")
        self.assertEqual(wer.parse_wer_file(path)["status"], "partial")


class DebuggerTests(Files):
    def transcript(self, time="Wed Jan 1 05:45:00.1234567 2025 (UTC + 5:45)", bucket="SYNTHETIC"):
        return f"Debug session time: {time}\nBUGCHECK_CODE: 139\nBUGCHECK_P1: 3\nBUGCHECK_P2: ffff`00000001\nBUGCHECK_P3: 0\nBUGCHECK_P4: 0\nPROCESS_NAME: example.exe\nMODULE_NAME: example\nSYMBOL_NAME: example+0x1\nFAILURE_BUCKET_ID: {bucket}\nLoading Dump File [C:\\Synthetic\\sample.dmp]\nSTACK_TEXT:\nsynthetic stack\n\n"

    def test_offsets_and_hex(self):
        result = debugger.parse_debugger_file(self.write("debug.txt", self.transcript()))
        row = result["records"][0]
        self.assertEqual(row["time_utc"], "2025-01-01T00:00:00.1234567Z")
        self.assertEqual(row["parameters"][1], "0xffff00000001")
        self.assertNotIn("dump_reference", row)

    def test_negative_half_hour(self):
        text = self.transcript(time="Tue Dec 31 20:30:00.000 2024 (UTC - 3:30)")
        self.assertEqual(debugger.parse_debugger_file(self.write("debug.txt", text))["records"][0]["time_utc"], "2025-01-01T00:00:00.0000000Z")

    def test_wrong_symbols(self):
        row = debugger.parse_debugger_file(self.write("debug.txt", self.transcript(bucket="WRONG_SYMBOLS_EXAMPLE")))["records"][0]
        self.assertIsNone(row["module"])
        self.assertIsNone(row["process"])

    def test_missing_timestamp_unknown(self):
        result = debugger.parse_debugger_file(self.write("debug.txt", "BUGCHECK_CODE: 1\n"))
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["records"][0]["time_utc"])

    def test_multiple_analyses_and_invalid_hex(self):
        for text in (self.transcript() * 2, self.transcript().replace("BUGCHECK_P1: 3", "BUGCHECK_P1: nope"), "no analysis"):
            with self.assertRaises(common.EvidenceError):
                debugger.parse_debugger_file(self.write("debug.txt", text))

    def test_details_opt_in(self):
        result = debugger.parse_debugger_file(self.write("debug.txt", self.transcript()), include_details=True)
        self.assertIn("synthetic stack", result["records"][0]["stack_text"])


class MinidumpTests(Files):
    def test_changed_file_rejected(self):
        path = self.write("synthetic.dmp", synthetic_dump())
        real_stat = os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            value = real_stat(fd); calls += 1
            return SimpleNamespace(st_size=value.st_size, st_mtime_ns=value.st_mtime_ns + calls)
        with mock.patch.object(minidump.os, "fstat", side_effect=changed), self.assertRaises(common.EvidenceError):
            minidump.parse_minidump_file(path)

    def test_nonmodule_stream_range_is_checked(self):
        data = bytearray(synthetic_dump(memory=True))
        struct.pack_into("<I", data, 52, 0xFFFFFFFF)
        with self.assertRaises(common.EvidenceError):
            self.parse(data)

    def parse(self, data, **kwargs):
        return minidump.parse_minidump_file(self.write("synthetic.dmp", data), **kwargs)

    def test_module_version_and_name(self):
        row = self.parse(synthetic_dump())["records"][0]
        self.assertEqual(row["name"], "example.dll")
        self.assertEqual(row["recorded_file_version"], "1.2.3.4")
        self.assertEqual(row["pe_timestamp_raw"], 0xDEADBEEF)

    def test_memory_stream_not_read(self):
        data = synthetic_dump(memory=True)
        result = self.parse(data)
        self.assertLess(result["metadata_bytes_read"], 512)
        self.assertGreater(result["file_size_bytes"], 1024 * 1024)

    def test_paths_opt_in(self):
        self.assertEqual(self.parse(synthetic_dump(), include_paths=True)["records"][0]["name"], "C:\\Synthetic\\example.dll")

    def test_invalid_version_signature(self):
        result = self.parse(synthetic_dump(valid_version=False))
        self.assertEqual(result["status"], "partial")
        self.assertIsNone(result["records"][0]["recorded_file_version"])

    def test_missing_module_stream(self):
        data = bytearray(synthetic_dump())
        struct.pack_into("<I", data, 32, 99)
        self.assertEqual(self.parse(data)["status"], "partial")

    def test_bad_headers_and_directory_bounds(self):
        for offset, value in ((0, 0), (4, 1), (8, 4097), (12, 0xFFFFFFFF), (40, 0xFFFFFFFF)):
            data = bytearray(synthetic_dump())
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(common.EvidenceError):
                self.parse(data)

    def test_truncation_every_prefix(self):
        data = synthetic_dump()
        for count in range(len(data)):
            with self.subTest(count=count), self.assertRaises(common.EvidenceError):
                self.parse(data[:count])

    def test_bad_module_count_and_name_rva(self):
        for offset, value in ((44, 4097), (44, 2), (68, 0xFFFFFFFF), (156, 65538), (156, 3)):
            data = bytearray(synthetic_dump())
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(common.EvidenceError):
                self.parse(data)

    def test_duplicate_module_stream(self):
        data = bytearray(synthetic_dump(memory=True))
        struct.pack_into("<III", data, 44, 4, 112, 56)
        with self.assertRaises(common.EvidenceError):
            self.parse(data)

    def test_invalid_utf16_and_nul(self):
        for suffix in (b"\x00\xd8", b"\x00\x00"):
            data = bytearray(synthetic_dump())
            struct.pack_into("<I", data, 156, 2)
            data[160:162] = suffix
            with self.assertRaises(common.EvidenceError):
                self.parse(data)

    def test_metadata_budget(self):
        with mock.patch.object(minidump, "MAX_READ_BYTES", 40), self.assertRaises(common.EvidenceError):
            self.parse(synthetic_dump())


class ManifestAvailabilityTests(unittest.TestCase):
    def test_missing_secure_primitives_fail_closed(self):
        with mock.patch.object(manifest.os, "supports_dir_fd", set()), self.assertRaises(common.EvidenceError):
            manifest.secure_root("unused-synthetic-root")


@unittest.skipUnless(os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"), "Secure manifest tests require POSIX/WSL")
class ManifestTests(Files):
    def test_platform_without_secure_open_fails_closed(self):
        obj = self.sample()
        with mock.patch.object(manifest.os, "supports_dir_fd", set()), self.assertRaises(common.EvidenceError):
            self.check(obj)

    def test_interrupted_read_does_not_modify_evidence(self):
        obj = self.sample()
        path = self.root / "evidence/sub/example.txt"
        with mock.patch.object(manifest, "open_relative", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.check(obj)
        self.assertEqual(path.read_bytes(), b"synthetic")
        self.assertEqual(self.check(obj)["status"], "complete")

    def test_extra_fields_and_invalid_hash_fail(self):
        obj = self.sample(); obj["files"][0]["sha256"] = "bad"
        with self.assertRaises(common.EvidenceError):
            self.check(obj)
        obj = self.sample(); obj["other"] = "ignored?"
        with self.assertRaises(common.EvidenceError):
            self.check(obj)

    def sample(self):
        self.write("evidence/sub/example.txt", b"synthetic")
        obj = {"schema_version": 1, "files": [{"path": "sub/example.txt", "size": 9, "sha256": hashlib.sha256(b"synthetic").hexdigest()}]}
        return obj

    def check(self, obj, **kwargs):
        return manifest.validate_manifest(self.json("manifest.json", obj), self.root / "evidence", **kwargs)

    def test_verified(self):
        self.assertEqual(self.check(self.sample())["status"], "complete")

    def test_traversal_absolute_ads_and_ambiguous_names(self):
        for name in ("../file", "/etc/passwd", "a/../b", "a//b", "C:/file", "a\\b", "a:stream", "./a", "a.", "a ", "NUL", "CON.txt", "a\x00b", "a/*"):
            obj = self.sample(); obj["files"][0]["path"] = name
            with self.subTest(name=name), self.assertRaises(common.EvidenceError):
                self.check(obj)

    def test_duplicates_and_schema(self):
        obj = self.sample(); obj["files"].append({**obj["files"][0], "path": "SUB/EXAMPLE.TXT"})
        with self.assertRaises(common.EvidenceError):
            self.check(obj)
        for bad in (True, -1, "9"):
            obj = self.sample(); obj["files"][0]["size"] = bad
            with self.assertRaises(common.EvidenceError):
                self.check(obj)

    def test_mismatch_and_missing(self):
        obj = self.sample(); obj["files"][0]["sha256"] = "0" * 64
        self.assertEqual(self.check(obj)["records"][0]["reason"], "hash_mismatch")
        obj["files"][0]["size"] = 8
        self.assertEqual(self.check(obj)["records"][0]["reason"], "size_mismatch")
        obj["files"][0]["path"] = "missing"
        self.assertEqual(self.check(obj)["status"], "partial")

    def test_symlink_leaf_and_parent(self):
        obj = self.sample()
        self.write("outside.txt", "synthetic")
        (self.root / "evidence/link").symlink_to(self.root / "outside.txt")
        obj["files"][0]["path"] = "link"
        self.assertEqual(self.check(obj)["status"], "partial")
        (self.root / "evidence/alias").symlink_to(self.root / "evidence/sub", target_is_directory=True)
        obj["files"][0]["path"] = "alias/example.txt"
        self.assertEqual(self.check(obj)["status"], "partial")

    def test_root_symlink_rejected(self):
        obj = self.sample()
        (self.root / "root-link").symlink_to(self.root / "evidence", target_is_directory=True)
        with self.assertRaises(OSError):
            manifest.validate_manifest(self.json("manifest.json", obj), self.root / "root-link")

    def test_fifo_rejected_without_blocking(self):
        obj = self.sample(); os.mkfifo(self.root / "evidence/pipe")
        obj["files"][0].update(path="pipe", size=0)
        self.assertEqual(self.check(obj)["records"][0]["reason"], "not_regular_file")

    def test_byte_budget(self):
        with self.assertRaises(common.EvidenceError):
            self.check(self.sample(), max_bytes=8)

    def test_change_during_hash(self):
        obj = self.sample()
        real_stat = os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            s = real_stat(fd); calls += 1
            keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            values = {k: getattr(s, k) for k in keys}
            if calls == 2:
                values["st_mtime_ns"] += 1
            return SimpleNamespace(**values)
        with mock.patch.object(manifest.os, "fstat", side_effect=changed):
            result = self.check(obj)
        self.assertEqual(result["records"][0]["reason"], "file_changed_during_hash")


class CorrelationTests(unittest.TestCase):
    def test_event_ids_and_negative_delta(self):
        anchors = [{"id": "later", "time_utc": "2025-01-01T00:00:00.0000001Z"}]
        result = report.correlate(self.source(), anchors, event_ids=[1000])
        self.assertEqual(result["records"][0]["delta_100ns"], -1)
        self.assertEqual(result["records"][0]["phase"], "before")
        self.assertEqual(report.correlate(self.source(), anchors, event_ids=[999])["records"], [])

    def test_malformed_normalized_metadata_rejected(self):
        source = self.source(); source["records"][0]["provider"] = []
        with self.assertRaises(common.EvidenceError):
            report.correlate(source, self.anchors())

    def source(self):
        return events.normalize_events([synthetic_event(1, "2025-01-01T00:00:00Z"), synthetic_event(2, "2025-01-01T00:00:00.0000001Z")])

    def anchors(self):
        return [{"id": "synthetic-incident", "time_utc": "2025-01-01T00:00:00Z"}]

    def test_exact_window_and_deltas(self):
        result = report.correlate(self.source(), self.anchors(), before_seconds=0, after_seconds="0.0000001")
        self.assertEqual([r["delta_100ns"] for r in result["records"]], [0, 1])
        self.assertIn("not causation", result["interpretation"])

    def test_filters_and_empty(self):
        result = report.correlate(self.source(), self.anchors(), providers=["Other"])
        self.assertEqual(result["summary"]["pairs"], 0)
        self.assertEqual(report.correlate(self.source(), [])["summary"]["incidents"], 0)

    def test_missing_and_duplicate_ids(self):
        for anchors in ([{"time_utc": "2025-01-01T00:00:00Z"}], self.anchors() * 2):
            with self.assertRaises(common.EvidenceError):
                report.correlate(self.source(), anchors)

    def test_caps_and_bad_windows(self):
        with self.assertRaises(common.EvidenceError):
            report.correlate(self.source(), self.anchors(), max_pairs=1)
        for value in ("NaN", "-1", "86401", "0.00000001", "bad"):
            with self.assertRaises(common.EvidenceError):
                report.correlate(self.source(), self.anchors(), before_seconds=value)

    def test_upstream_partial_propagates(self):
        source = self.source(); source["status"] = "partial"
        self.assertEqual(report.correlate(source, self.anchors())["status"], "partial")

    def test_markdown_escapes(self):
        anchors = self.anchors(); anchors[0]["id"] = '<script>|[click](https://invalid.example)'
        text = report.markdown_report(report.correlate(self.source(), anchors))
        self.assertNotIn("<script>", text)
        self.assertIn("\\|", text)
        self.assertIn("\\[click\\]", text)


class CliTests(Files):
    def test_wer_debugger_and_manifest_cli(self):
        wer_path = self.write("sample.wer", "EventType=APPCRASH\nReportIdentifier={00000000-0000-0000-0000-000000000001}\n")
        self.assertEqual(self.call("wer", wer_path)[0], 0)
        dbg_path = self.write("dbg.txt", "BUGCHECK_CODE: 1\n")
        self.assertEqual(self.call("debugger", dbg_path)[0], 2)
        if os.open in os.supports_dir_fd:
            self.write("evidence/file.txt", b"synthetic")
            mf = self.json("manifest.json", {"schema_version": 1, "files": [{"path": "file.txt", "size": 9, "sha256": hashlib.sha256(b"synthetic").hexdigest()}]})
            self.assertEqual(self.call("manifest", mf, "--root", self.root / "evidence")[0], 0)

    def test_documented_examples(self):
        examples = Path(__file__).resolve().parents[1] / "examples"
        self.assertEqual(self.call("events", examples / "events.synthetic.json")[0], 0)
        self.assertEqual(self.call("wer", examples / "report.synthetic.wer")[0], 0)
        self.assertEqual(self.call("debugger", examples / "debugger.synthetic.txt")[0], 0)

    def call(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(list(map(str, args)))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_events_end_to_end_and_no_overwrite(self):
        source = self.json("events.json", [synthetic_event()])
        output = self.root / "normalized.json"
        self.assertEqual(self.call("events", source, "--output", output)[0], 0)
        saved = output.read_bytes()
        self.assertEqual(self.call("events", source, "--output", output)[0], 1)
        self.assertEqual(output.read_bytes(), saved)

    def test_input_cannot_be_output(self):
        source = self.json("events.json", [synthetic_event()]); saved = source.read_bytes()
        self.assertEqual(self.call("events", source, "--output", source)[0], 1)
        self.assertEqual(source.read_bytes(), saved)

    def test_partial_and_fatal_exit_codes(self):
        source = self.json("events.json", [{}])
        self.assertEqual(self.call("events", source)[0], 2)
        result = self.call("events", self.root / "private-path-missing.json")
        self.assertEqual(result[0], 1)
        self.assertNotIn("private-path", result[2])

    def test_correlation_cli(self):
        source = self.json("events.json", events.normalize_events([synthetic_event()]))
        incidents = self.json("incidents.json", [{"id": "example", "time_utc": "2025-01-01T00:30:00Z"}])
        code, text, _ = self.call("correlate", "--events", source, "--incidents", incidents, "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertIn("Temporal association only", text)

    def test_minidump_cli(self):
        source = self.write("synthetic.dmp", synthetic_dump())
        code, text, _ = self.call("minidump", source)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["records"][0]["recorded_file_version"], "1.2.3.4")

    def test_input_size_limit(self):
        source = self.write("large.txt", b"12345")
        with self.assertRaises(common.EvidenceError):
            common.read_bytes(source, 4)


if __name__ == "__main__":
    unittest.main()
