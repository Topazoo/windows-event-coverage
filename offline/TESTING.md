# Validation evidence and development

Local package validation: Ubuntu 24.04 under WSL, Python 3.12.3; **80 unittest tests passed with no skips** before repository integration. Integration adds a cross-platform fail-closed contract test (81 total). Tests containing loops also exercise individual malformed inputs as subtests, including every truncated prefix of a generated module-bearing minidump. No real diagnostics were used and no local package/runtime was installed.

```bash
python3 -m unittest discover -s tests -v
```

Coverage exercised:

- Exact 100ns UTC roundtrips, positive/negative minute offsets, pre-epoch values, invalid calendars/offsets and ambiguous timestamp rejection.
- Event JSON/CSV/XML, BOM-marked UTF-16, duplicate System/CSV/JSON fields, repeated/unnamed EventData, unsupported UserData, truncation notices, malformed rows, exact window endpoints, ID reuse, missing IDs and collector coverage propagation.
- WER allowlists, multidigit signature indices, encoding/size limits, repeated fields, conflicting/invalid/missing IDs, exact duplicate handling and FILETIME conversion.
- Saved-debugger hexadecimal fields, minute-offset timestamps, wrong symbols, missing timestamps, multiple-analysis rejection and optional details.
- Generated minidump module metadata; every truncated prefix; invalid header/version/directory/RVA/count/string; duplicate module streams; malformed UTF-16; metadata-read budget; changed-file rejection. A fixture with a 1 MiB memory stream requires less than 512 bytes of metadata reads.
- Manifest schema, byte budget, traversal/absolute/ADS/device/case-collision rejection, hashes/sizes/missing files, root/parent/leaf symlinks, nonblocking FIFO rejection, change during hashing, interruption and fail-closed unsupported platforms.
- Correlation filters, asymmetric/exact windows, signed deltas, duplicate/missing anchors, pair caps, partial coverage propagation and Markdown escaping.
- All CLI commands, documented examples, output no-overwrite, input/output collision and error codes. Errors do not echo raw filesystem paths.

Test source is `tests/test_offline.py`. It uses only unittest, temporary files, deterministic synthetic inputs and mocks for read interruption/file-change conditions. Generated fixtures are removed by TemporaryDirectory cleanup. No external test framework, fuzzy network service or original evidence file is required.

Limits of this evidence:

- This is not exhaustive fuzzing, a full security audit, compatibility proof for every WER/debugger variant, or validation against live Windows logs.
- Repository CI runs Python 3.12 on Ubuntu and Windows within the existing required synthetic checks. All 81 tests are eligible on Ubuntu; 12 POSIX manifest tests explicitly skip on Windows. A separate fail-closed contract runs on both. Refer to the linked PR/commit Actions result for execution status. Python 3.10/3.11 remain unverified.
- Hash metadata-change tests simulate detectable races. They do not establish immunity against privileged adversaries, changing mount topology or an attacker who controls both manifests and evidence.
- Interrupted CLI output may leave a new incomplete file. Existing inputs/outputs are not overwritten; callers must check the exit status and parse the output before use.
- Packaging installation is not exercised: all tests run from source without pip dependencies. Hosted CI is configured in the repository root workflow; no real-evidence validation is implied by a green run.

Before publication, rerun this suite and inspect the exact staged file set. Only source, synthetic text examples, tests, documentation, license and packaging metadata belong in the release. `outputs/`, private inputs, bytecode caches, real dumps and EVTX files are ignored.
