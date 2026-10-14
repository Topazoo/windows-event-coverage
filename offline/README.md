# Windows Evidence Offline

Parse explicitly supplied Windows evidence files and produce normalized JSON and noncausal correlation reports. This package makes uncertainty visible: missing identifiers stay separate, conflicting records are retained, rejected rows are counted, and upstream collector coverage failures survive normalization.

Python 3.10+; **standard library only**. Run from this checkout with no installation:

```bash
python3 -m win_evidence --help
python3 -m unittest discover -s tests -v
```

The package reads only named inputs. It has no live event querying, directory discovery, elevation, debugger invocation, downloads, network access, system changes or checkpoint updates. Inputs are never rewritten. Output files use exclusive creation and refuse to overwrite existing files. On interruption an incomplete output can remain; use a new output name and do not treat invalid JSON as evidence.

## Quick start with synthetic inputs

```bash
mkdir -p outputs
python3 -m win_evidence events examples/events.synthetic.json \
  --from-utc 2025-01-01T00:00:00Z --through-utc 2025-01-01T01:00:00Z \
  --output outputs/events.json
python3 -m win_evidence correlate --events outputs/events.json \
  --incidents examples/incidents.synthetic.json \
  --before-seconds 120 --after-seconds 120 --format markdown \
  --output outputs/correlation.md
python3 -m win_evidence wer examples/report.synthetic.wer
python3 -m win_evidence debugger examples/debugger.synthetic.txt
```

These example files contain invented data. The binary minidumps used in tests are generated in temporary directories and are not bundled as dump files.

## Commands

| Command | Input / behavior |
|---|---|
| `events FILE` | JSON event array, published collector run v1, CSV export or Event/Events XML. Optional `(from, through]` timestamp filter. |
| `wer FILE [FILE ...]` | Up to 1,000 explicitly named WER files. Keeps ambiguous/missing IDs distinct; collapses byte-identical reports only when the report ID is valid. |
| `debugger FILE` | One saved English WinDbg kernel bugcheck analysis. Parses timestamp offsets including minutes; suppresses known wrong-symbol attribution. |
| `minidump FILE` | Reads bounded header/directory/module/name metadata directly. Never reads memory streams or loads a module. |
| `manifest FILE --root DIRECTORY` | Verifies only listed relative file paths, lengths and SHA256 values. Root and descendant symlinks are rejected using directory descriptors. Requires WSL/Linux/POSIX support. |
| `correlate --events FILE --incidents FILE` | Joins normalized events to distinct incident anchors using independent before/after windows; emits JSON or escaped Markdown. |

All commands accept `--output NEW_FILE`, defaulting to stdout. **Exit codes:** 0 = supported input processed without reported issues; 2 = partial result, coverage warning, conflict or duplicate notice; 1 = fatal input/I/O failure. Argument syntax errors use argparse's exit code 2 and print usage, not result JSON. “Complete” refers only to processing the supplied files, never to live log coverage or system health.

Payload text, event Data, WER signatures/paths and debugger stack/path details are omitted by default. Explicit flags are `events --include-payload`, `wer --include-signatures --include-paths`, `debugger --include-details` and `minidump --include-paths`. These flags expose source content; even default metadata, identifiers, names and hashes can be sensitive. There is no claim of anonymization. Keep actual inputs and outputs private.

Event inputs use `Channel`, `RecordId`, `TimeUtc`, `Provider`, `Id`, `Level`, and optional `Data`/`DataJson`/`Message`. The published `windows-event-coverage` run format is accepted directly. Named EventData is represented as an array so duplicate names and unnamed fields survive XML parsing. The normalizer does not re-parse Message text into application-specific facts. Legacy already-overwritten DataJson fields cannot be recovered. XML UserData is not interpreted and is flagged when payload output is requested. See [SCHEMAS.md](SCHEMAS.md).

Correlation accepts repeated `--provider NAME` and `--event-id NUMBER`, `--before-seconds` / `--after-seconds` from 0 to 86400 with at most 100ns precision, and `--max-pairs` (default 100000). Window endpoints are inclusive. Incident IDs must be nonempty and unique: the tool will not guess that two reports describe the same crash. Timestamps require explicit offsets; all output timestamps are normalized to UTC with seven fractional digits. Counts are event records, not independent failures. Delayed reporting, gaps and clock changes prevent temporal proximity from proving causation.

## Manifest verification

```json
{
  "schema_version": 1,
  "files": [
    {"path": "sub/example.txt", "size": 9,
     "sha256": "PUT_THE_64_HEX_CHARACTER_SHA256_HERE"}
  ]
}
```

Supply your actual expected digest; the placeholder intentionally is not a valid manifest. `--max-bytes` sets the total declared hashing budget (default 128 MiB). Extra fields, malformed digests, duplicate/case-colliding paths, parent traversal, absolute paths, Windows drive/ADS syntax, reserved device names and ambiguous path components are rejected before evidence files open. Each listed file must be regular, have the expected size, remain metadata-stable during hashing, and match its digest. Root/parent/leaf descriptors are opened with `O_NOFOLLOW`; named pipes cannot block the read. Native Windows deliberately fails closed here: use WSL, rather than a weaker pathname-only check.

A manifest is an integrity assertion, not authentication. An attacker able to replace both evidence and expected hashes can forge a valid set. Hard links and mount points are not rejected; the explicitly chosen root must be trusted. Concurrent privileged/mount changes and filesystem-specific semantics are outside the guarantee. A hash validates the bytes read, not a historical acquisition time. No unlisted files are scanned; a valid manifest does not establish directory or incident completeness.

## Limits and development

- Text input: 32 MiB maximum; event XML and debugger text: 8 MiB; WER: 1 MiB per file, 8192 characters per selected value. UTF-8 or BOM-marked UTF-16 only; no guessed legacy encoding.
- Events: 100000 rows. Minidumps: 4096 streams/modules, 64 KiB per module name and 8 MiB metadata-read budget. Invalid ranges fail before reading; no tolerant recovery from malformed binary input.
- Correlation: 10000 incident anchors; bounded pair count checked before constructing output. No silent truncation.
- No native EVTX reader, full-memory/kernel-dump parser, symbol resolution, malware classification, root-cause verdict or live capture is included.
- Debugger parsing handles the documented English kernel-analysis fields only. Unrecognized timestamps remain unknown; multiple analyses per file are rejected. Module PE timestamps are kept as raw integers because they may represent reproducible-build values.
- Parser code is portable standard-library Python. Local validation uses native Ubuntu/WSL Python 3.12; repository CI additionally runs Python 3.12 on Ubuntu and Windows. POSIX manifest tests skip on Windows, where verification fails closed. Python 3.10/3.11 execution is not claimed. Manifest verification requires secure POSIX open semantics.

Tests generate their own text/binary files and clean up temporary directories. See [TESTING.md](TESTING.md) for coverage and limitations. Do not point tests at original diagnostics. There are no runtime dependencies; optional wheel building via `pyproject.toml` uses setuptools, which is not installed or downloaded by this project.

## Provenance and license

MIT; see [LICENSE](LICENSE) and [PROVENANCE.md](PROVENANCE.md). This is newly written Python code based on reviewed collection/analysis requirements. No original private diagnostic script, report, dump, debugger binary or third-party implementation is bundled.
