# Hardware, saved sensors and local dashboard

This optional component uses PowerShell 7.2+ and Python 3.10+ with no added dependencies. It is an original extraction of reusable requirements from an earlier private toolkit. Private database schemas, investigation narratives, launchers and runtime data are excluded. MIT covers this code; HWiNFO and user-supplied exports retain their own terms. No HWiNFO code, driver or binary is included.

## Windows hardware inventory — explicit opt-in

```powershell
# Safe default: prints the collection plan without querying hardware
pwsh -NoProfile -File telemetry/Collect-Hardware.ps1
# User-selected live operation; do not run merely to preview the dashboard
pwsh -NoProfile -File telemetry/Collect-Hardware.ps1 -Collect -OutputPath hardware.json
```

Queries selected CPU, RAM, graphics and OS properties through existing CIM permissions, with a 15-second operation timeout per query. No elevation, firmware access, driver installation, stress workload, registry writes or collector coordination changes. Output omits hostnames, serial numbers and hardware UUIDs. Model and driver names can still be identifying; keep real output private. A CIM timeout is not a strict whole-process deadline. Unavailable hardware is not proven absent.

`hardware-inventory-v1` contains `startedUTC`, `completedUTC`, and `components`: each has `component`, `status` (`read`, `empty`, `failed`) and allowlisted `rows`. Failure messages are omitted because they can expose private paths. Exit 2 means at least one component was empty/failed; fatal errors terminate. A new output is reserved exclusively before collection. Interruption can leave an empty/incomplete file; it is not a valid completed snapshot and is never overwritten automatically. There is no checkpoint or background loop.

## Import an existing sensor CSV

```bash
python3 telemetry/telemetry.py sensors telemetry/examples/sensors.synthetic.csv --output sensors.json
# For an explicitly known Windows-1252 semicolon export:
python3 telemetry/telemetry.py sensors YOUR.csv --encoding cp1252 --delimiter ';' --output sensors-new.json
```

This is saved-export ingestion, **not live sensor capture**. Capture through the separately installed tool of your choice; this repository does not start or automate HWiNFO. UTF-8 with optional BOM is the default; UTF-16 and Windows-1252 require explicit selection. CSV delimiter is explicit. At most 8 MiB, 20,000 rows and 2,048 columns are processed. Exactly one `Date` and one `Time` heading are required. Duplicate sensor headings retain separate zero-based column indices.

`sensor-table-v1` records source SHA256, encoding/delimiter, columns, samples and gaps. Sample `row` is the CSV record ordinal (quoted multiline cells can span physical lines); `values` and `localClock` are original strings. No numeric conversion, locale/date parsing, timezone inference or UTC alignment is performed. `timezone` is null. `parsed` means structurally accepted, not a validated measurement. A full-width footer with nonempty clock fields cannot reliably be distinguished from data; review your export. Repeated headers, mismatched widths, blank clock fields, duplicate local clocks, row caps and fewer than two samples produce explicit gaps and exit 2. Fatal decoding/schema/I/O errors exit 1. No rejected raw rows are included.

## Passive dashboard

```bash
python3 telemetry/telemetry.py dashboard --sensors sensors.json --hardware telemetry/examples/hardware.synthetic.json --output dashboard.html
```

Open `dashboard.html` locally. It displays saved JSON with escaped text, no JavaScript, remote assets, server, upload, collection buttons or automatic refresh. Either input is optional; at least one is required. Schema identifiers are checked, but this viewer is not an integrity verifier or complete schema validator. Inputs remain untrusted observations. Generated HTML includes their content: do not publish real dashboards. All outputs use exclusive creation; choose a new name to repeat.

## Development and limits

```bash
python3 -m unittest discover -s telemetry -p 'test_*.py' -v
pwsh -NoProfile -File telemetry/Test-Hardware.ps1
```

Tests use invented exports only. Real HWiNFO version/locale combinations and live Windows CIM behavior have not been validated by this extraction. No fan control, SMART access, physical sensor driver, shared-memory reader or causal diagnosis is provided. Hardware inventory is a separate opt-in operation; passive viewing cannot alter it. Source review found the original release copy inaccessible but independent authored development sources readable; no protected release data or security changes were needed.
