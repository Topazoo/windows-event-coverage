# JSON schemas, version 1

This document is the normative field reference. JSON is strict: duplicate object keys, NaN and Infinity are rejected. Files use UTF-8 or BOM-marked UTF-16. Unknown event source fields can be ignored, but manifest fields are exact and closed. Output JSON uses ASCII escapes where needed.

## Common envelope

Every successful or partial command emits an object with:

| Field | Type / meaning |
|---|---|
| `schema_version` | Integer `1` |
| `kind` | `events`, `wer`, `debugger`, `minidump_modules`, `manifest`, `correlation` |
| `status` | `complete` or `partial` |
| `records` | Array, possibly empty |
| `issues` | Array of objects with `code` and optional zero-based `index`/`file_index` or channel metadata |
| `rejected` | Number of rejected event rows or WER files; zero for other commands |

Fatal errors produce no successful JSON envelope. A partial result never implies that the absent evidence was empty. Duplicate-removal notices deliberately make the result partial, even where all retained records are valid. Consumers should inspect the issue codes rather than equating every partial result with invalid records.

`source_id` is SHA256 of the bytes of the explicitly supplied text file. In direct Python `normalize_events()` calls it defaults to the literal `explicit-input`, unless supplied by the caller. It is provenance within this processing run, not a verified acquisition identity. `source_index` identifies the zero-based original row. Minidumps are not fully hashed; no full-dump source hash is claimed.

## Events

Accepted JSON input is an array of records with `Channel` (nonempty string), `TimeUtc` (offset-bearing timestamp), `Id` (0..65535), optional `RecordId` (positive uint64), `Provider` (string/null), `Level` (0..255). Numeric CSV fields may be decimal strings. Booleans/fractions are not integers. A missing record ID preserves a distinct record and reports an issue. CSV headers must be unique. XML supports `Event` or `Events` roots, with namespace-insensitive System and EventData children; DTD/entity declarations and duplicate System fields are rejected.

Collector input uses `{ "SchemaVersion": 1, "Channels": [...], "Events": [...] }`. Non-complete channel statuses or nonempty gaps become `upstream_coverage_not_complete` issues. Source error messages are not copied into output.

Normalized records: `source_id`, `source_index`, `channel`, `record_id` (integer/null), `time_utc`, `provider` (string/null), `event_id`, `level` (integer/null). Payload opt-in adds `message` and `data`, an array of `{ "name": string-or-null, "value": source-value }`. Named duplicates remain multiple entries. Legacy DataJson objects become an array of name/value pairs; duplicate JSON keys are rejected. Raw XML is never copied to output.

`selection` contains normalized `from_exclusive_utc`, `through_inclusive_utc` (both null or both present), and `payload_included`. Bounds use integer 100ns arithmetic. Known truncation flags generate issues when payload is requested. Equivalent complete input rows with the same channel/record ID collapse; different rows sharing that ID remain as a conflict/reset possibility. Missing IDs never collapse. This does not implement cross-file/log-generation deduplication.

Common event codes: `outside_window`, `invalid_event_record`, `missing_record_id_preserved`, `exact_duplicate_removed`, `record_id_reuse_or_conflict_preserved`, `truncated_source_payload`, `unsupported_userdata_payload_omitted`, `upstream_coverage_not_complete`.

## WER

Each record contains `source_id`, `file_index` (batch parser), `report_id` (normalized UUID/null), `time_utc` (FILETIME converted exactly/null), and `fields` (ordered name/value array). Repeated keys are retained. Base allowlist: EventType, EventTime, ReportIdentifier, IntegratorReportIdentifier, AppName, AppVersion, ApplicationName and ReportStatus. Optional paths: AppPath, ApplicationPath. Optional signatures: Sig/DynamicSig indices 0..9999, Name/Value. Other keys, including CommandLine, are omitted.

ReportIdentifier must be valid and unambiguous. IntegratorReportIdentifier is retained as a separate field, never silently substituted as identity. Files with no usable ID are never merged. Byte-identical files with the same valid ID collapse; a shared ID with different bytes is preserved and flagged. Unknown encoding or malformed/oversized input rejects that file while others remain usable. `selection` records path/signature opt-ins.

Common codes: `duplicate_wer_field_preserved`, `invalid_report_identifier`, `conflicting_report_identifiers`, `missing_unambiguous_report_id_preserved`, `invalid_wer_filetime`, `ambiguous_wer_filetime`, `invalid_or_unreadable_wer_file`, `exact_report_duplicate_removed`, `report_id_conflict_preserved`.

## Saved debugger analysis

Single record: `source_id`, `bugcheck` (canonical hex string), four `parameters` (hex/null), `time_utc` (UTC/null), `symbol_status`, `process`, `module`, `symbol`, `bucket`. `WRONG_SYMBOLS...` buckets set attribution fields to null and `symbol_status` to `unresolved`; otherwise it is `not_independently_verified`, not a promise of matching symbols. Optional details add `dump_reference` and `stack_text`. They are references/text only and are never opened or executed.

Missing parameters/timestamp and wrong symbols are issues; malformed hex, repeated fields or multiple sessions/bugchecks are fatal. Timestamp grammar is English month/day/time/year plus an explicit `(UTC +/- H:MM)` offset.

## Minidump module metadata

Header must have MDMP signature and low version bits 0xA793. Only stream type 4 is decoded. A record contains `module_index`, `name` (basename by default), `base_address` (hex), `image_size`, `checksum`, `recorded_file_version` (four components/null), `pe_timestamp_raw`. The version is recorded data, not a read of the current binary.

Envelope additions: `file_size_bytes`, `metadata_bytes_read`, `header_timestamp_raw` when module stream is present, and interpretation text. Absent module stream gives an empty partial result. Invalid version-info signature gives null version and an issue. Every stream range is checked, even if its payload is not read. Invalid names/counts/RVAs/ranges are fatal; memory-stream data is never read.

## Integrity manifest

Input has exactly `schema_version` and `files`. `files` contains 1..10000 entries, each with exactly `path` (portable relative slash-separated name), `size` (nonnegative integer), `sha256` (64 hex digits). No absolute/parent/empty/dot/backslash/ADS/control/device-name/case-colliding paths. Paths are relative to the caller's separately specified trusted root.

Output records contain `path`, `status` (`verified`/`failed`), and either verified `size`/`sha256` or `reason`. Reasons include `not_regular_file`, `size_mismatch`, `hash_mismatch`, `file_grew_during_hash`, `file_changed_during_hash`, `missing_denied_or_unsafe_path`. Schema/path/budget errors are fatal before file verification. Missing/denied/unsafe listed files result in a partial envelope.

## Correlation

Input events: normalized `events` envelope above. Incident input: array of `{ "id": "distinct-nonempty-string", "time_utc": "offset-bearing-time" }`. Extra incident properties are ignored; IDs must not be missing or duplicated. A source event partial status/issues/rejections propagate as `source_event_coverage_partial`.

Output pairs contain `incident_id`, `incident_time_utc`, `event_index` (index into normalized input), `event_source_id`, `event_source_index`, `channel`, `record_id`, `provider`, `event_id`, `event_time_utc`, signed `delta_100ns`, and `phase` (`before`/`at`/`after`). Selection records independent inclusive before/after windows and optional provider/ID filters. Summary contains selected record count, incident count, pair count, and channel/provider/event-ID clusters. A record can match multiple incident windows; pair count is not a count of unique events or crashes. Exceeding the pair cap is fatal, with no truncated-success output.
