# Windows Event Coverage

Collect Windows event metadata with explicit coverage gaps, then analyze saved evidence offline. The repository has two independent components:

| Component | Purpose | Runtime |
|---|---|---|
| **Collector** — root PowerShell scripts | Read bounded event windows, retry failed channels, and save per-channel checkpoints and coverage receipts. | Live collection: Windows with PowerShell 7.2+. |
| **Offline analysis** — [`offline/`](offline/) | Parse explicit event, WER, saved-debugger and minidump metadata files; validate evidence manifests; produce noncausal correlation reports. | Python 3.10+, standard library only. Hardened manifest verification requires WSL/Linux/POSIX. |

Collection and analysis are separate operations. The Python package never queries live Windows logs, invokes a debugger, discovers files, elevates privileges or advances collector checkpoints. Neither component diagnoses a crash cause or certifies system health. No private diagnostic logs, real dumps or debugger binaries are bundled.

## Collect an explicit event window

Edit a copy of [`examples/config.json`](examples/config.json) to choose a recent UTC start, channels, System XPath predicates, page size and record cap. Then run from the repository root on Windows:

```powershell
pwsh -NoProfile -File ./Collect.ps1 `
  -ConfigPath ./examples/config.json `
  -StateDirectory ./state `
  -ThroughUtc 2025-01-02T00:00:00Z
```

The dates above are examples; choose the actual interval you intend to review. Collection uses **(start, end]** UTC bounds and validates every returned timestamp. Repeat with the same configuration/state directory and a later end. Successful channels advance independently; failed, denied, disabled or capped attempts preserve their checkpoints and are retried. Configuration changes require a new state directory.

A state-directory lock excludes concurrent writers. Immutable run files are written before the checkpoint commit. Retention gaps and record-ID decreases remain explicit; a successful read does not recover lost history. Generated records omit messages, XML, computer identities and payloads, but metadata can still be sensitive. Use only existing read permissions; the script does not enable logs or elevate.

Collector exit codes: 0 for all channels complete without detected gaps, 2 for a gap/failure, and PowerShell errors for fatal configuration/storage/locking problems. See [collector usage, JSON format and limitations](docs/COLLECTOR.md).

## Analyze synthetic examples offline

No installation or external Python packages are needed. From the repository root, enter `offline/` and run with an existing Python interpreter (`python3` in WSL/Linux, `python` on Windows):

```bash
cd offline
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

The correlation example selects three event records and matches two to the incident window, preserving a 100ns offset. It reports temporal association, **not causation**. Output files must be new: existing files are never overwritten. Use new names when repeating these commands.

The `events` command also accepts a collector `run-*.json` directly. It preserves upstream coverage warnings. `minidump FILE` reads only bounded module metadata, not memory streams. WER signatures/paths, event payloads and debugger details require explicit opt-ins. Missing identifiers remain separate; conflicting records are retained and flagged.

For manifest verification:

```bash
python3 -m win_evidence manifest manifest.json --root /path/to/evidence
```

This command requires **WSL/Linux/POSIX directory-descriptor support**. It rejects traversal, ambiguous paths, symlinks and nonregular files, then checks listed lengths and SHA256 values within a byte budget. **Native Windows fails closed for this command**; no Windows manifest-verification capability is claimed. Hash verification establishes listed bytes, not provenance authenticity or evidence completeness.

See the [offline CLI and limits](offline/README.md), [schema reference](offline/SCHEMAS.md), and [test coverage](offline/TESTING.md). Offline exit codes are 0 for complete processing, 2 for partial results/warnings, and 1 for fatal input/I/O failures; argument syntax errors also use code 2 with usage text.

## Development and validation

```powershell
# Collector synthetic tests, from the repository root
pwsh -NoProfile -File ./tests/Run-Tests.ps1

# Offline synthetic tests, from the repository root
python -m unittest discover -s offline/tests -t offline -v
```

Alternatively, enter `offline/` and run `python3 -m unittest discover -s tests -v`. From WSL, [`tests/run-wsl.sh`](tests/run-wsl.sh) runs the collector suite with an existing PowerShell runtime; Windows interoperability is labeled explicitly when used.

The required GitHub checks retain their names: `synthetic (windows-latest)` and `synthetic (ubuntu-latest)`. Each runs the existing collector suite and the offline Python 3.12 suite. POSIX manifest tests run on Ubuntu and explicitly skip on Windows; a separate fail-closed contract test runs on both. Workflow permissions remain read-only, actions are pinned, and checkout credentials are not persisted. See [Actions](https://github.com/Topazoo/windows-event-coverage/actions) for the result of each commit.

Local development validation used native WSL Python 3.12.3 and generated evidence only. Test minidumps are assembled in temporary directories. Synthetic tests do not establish compatibility with every real Windows export, WER/debugger variant, Python version or filesystem. No real-event collection, protected read, restart trial, symbol-resolution test or exhaustive security audit is part of this integration. Live collection remains Windows-only; offline manifest verification remains POSIX-only.

Keep actual inputs and outputs private. Payload opt-ins are not anonymization. Publication should contain only source, tests, invented examples, documentation and license files.

## License and provenance

MIT; see [LICENSE](LICENSE). Both components are original implementations of requirements developed during a private investigation. No private investigation artifacts or third-party implementations are bundled. The offline package records its scope in [PROVENANCE.md](offline/PROVENANCE.md); third-party runtimes and any user-supplied evidence retain their own licenses.
