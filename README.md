# Windows Event Coverage

A small Windows event collector that makes incomplete coverage visible. It queries a fixed UTC window, paginates every channel, validates every returned timestamp, and saves independent channel checkpoints. Failed channels are retried on the next invocation.

This is a new, standalone implementation of collection patterns developed during a private diagnostic investigation. No diagnostic evidence or original investigation scripts are distributed. It is not a crash diagnosis engine.

## Requirements and usage

Live collection requires PowerShell 7.2 or later on Windows and permission to read the chosen event channels. No external modules, executables, administrator launcher, or installation step are provided. Use existing access; denied channels are reported.

Edit a copy of `examples/config.json`: choose an explicit UTC `StartUtc`, channels, Windows Event Log System XPath predicates, page size and per-channel record cap. The window is **(start, end]**: start excluded, end included. Timestamps require `Z` or `+00:00`.

```powershell
pwsh -NoProfile -File ./Collect.ps1 -ConfigPath ./examples/config.json -StateDirectory ./state -ThroughUtc 2025-01-02T00:00:00Z
```

Use a recent start/end when collecting your own logs. Repeat with a later end and the same configuration/state directory. Each successful channel starts at its own saved end. Failed, disabled and denied channels start at their last success (or original start), even if other channels have advanced. Configuration changes require a new directory; existing state is never silently reinterpreted. JSON property ordering is currently part of configuration identity, so keep the same file.

Exit code 0 means all channels completed without detected gaps; 2 means at least one gap/failure; fatal configuration/storage/locking errors produce PowerShell errors. Inspect the JSON, not only the exit code. A complete result is limited to the selected predicates and detectable retention, not proof of system health or full historical retention.

## Persistence and concurrency

A filesystem lock held with exclusive sharing covers each entire invocation. Use a single state directory per machine/configuration on a local filesystem. Do not delete or replace its `.lock` file while a collector runs. A crash releases the handle; the file may remain and is safely reused.

Each run writes an immutable `run-<random>.json` containing metadata-only events and coverage. The run file is flushed and atomically renamed before the checkpoint is flushed and atomically replaced. `checkpoint.json` is the commit point and references the latest committed run. A crash between writes can leave an orphan run: it is not committed evidence and the window will be retried. Consumers must deduplicate replayed records by channel/window/run provenance; record IDs alone can be reused after clearing a log. A filesystem/power failure may still lose directory updates; no power-loss guarantee is claimed. Keep run files if retaining historical gap evidence.

A failed page, bad timestamp, non-increasing record ID, retention change during collection or cap overflow discards that channel's entire attempt and preserves its checkpoint. Caps are exact: one extra record distinguishes a full window at the cap from overflow. If a channel repeatedly exceeds the cap, collect a shorter end window or use a fresh configuration with a larger cap; there is no partial-page resume.

## Coverage JSON v1

Run root: `SchemaVersion` (1), `ThroughUtc` (requested end), `Channels` (coverage array), `Events` (validated metadata array).

Each channel contains:

| Field | Meaning |
|---|---|
| `Channel` | Configured channel name |
| `FromUtc`, `ThroughUtc` | Requested exclusive/inclusive bounds |
| `Status` | `complete`, `complete-with-gaps`, `failed`, `denied`, or `disabled` |
| `SelectedRecords` | Committed event count, zero on failure |
| `Gaps` | `retention-start-after-window-start` and/or `record-id-decreased` |
| `Error` | Failure message, otherwise null |
| `Snapshot` | Initial `OldestId`, `NewestId`, `OldestUtc`; null if unavailable |

Events contain `Channel`, `RecordId`, `TimeUtc`, `Id`, `Level`, and `Provider`. Message text, XML, computer identity and event payloads are omitted. Even metadata and error text can be sensitive: keep generated state private. Missing/invalid channel names and unsupported queries are `failed`; access errors are `denied` when Windows exposes an access-denied exception. Unknown errors remain `failed`, never empty success.

Checkpoint root: `SchemaVersion`, `Configuration` (serialized selection configuration), `LastRun` (committed filename), and `Channels` keyed by channel with `ThroughUtc` and `NewestId`. Failure status lives in the run; absence of a channel checkpoint means no successful window yet. `complete-with-gaps` advances the checkpoint while preserving the gap in the immutable run. It does not certify missing history.

## Limitations

- Windows Event Log has no transactional snapshot here. A starting high record ID bounds pagination; before/after retention checks detect common changes but cannot detect every clear/refill race or clock change.
- Oldest retained time after the start is a conservative possible rollover gap. An empty channel does not prove historical absence. Record IDs can reset and events can arrive late or have nonmonotonic clocks; late events timestamped before an advanced checkpoint can be missed. Use a new state directory for an overlapping audit window.
- Predicates are trusted Windows XPath, passed as query data, not executed as PowerShell. Their semantics are not independently re-evaluated; timestamps and record IDs are validated independently.
- No EVTX export, payload capture, dump collection, remediation, scheduling, or protected access escalation is included.
- Linux/WSL can develop and run synthetic tests with an existing PowerShell installation; `Get-WinEvent` live collection is Windows-only. No live collection is exercised by tests.
- Local filesystem locking/rename semantics are required; network shares and concurrent state-directory replacement are unsupported.

## Development

```powershell
pwsh -NoProfile -File ./tests/Run-Tests.ps1
```

The dependency-free tests inject synthetic metadata/page readers, including boundaries at 100ns precision, pagination, cap overflow, denied/disabled retries, rollover, reset, interruption, configuration drift and locking. On Windows they also test failed atomic replacement retaining the previous file. Temporary fixtures are placed in the OS temp directory. Do not use production checkpoints as fixtures. Real Windows adapter behavior and destructive log-clear races require a separately authorized disposable Windows environment.

From WSL, run `bash tests/run-wsl.sh` with Git, Python 3 and an existing Linux `pwsh` on PATH. The script checks staged whitespace and example JSON before the synthetic suite. If only Windows PowerShell is available, explicitly pass its WSL path: `bash tests/run-wsl.sh /mnt/c/path/to/pwsh.exe`. That mode runs the suite through WSL interoperability and labels it as a Windows runtime; it does not establish native Linux runtime compatibility. No tool installation or live collection is performed.

Before publication, inspect every tracked file and every commit for personal paths, actual logs, identifiers, credentials and third-party binaries. Only source, synthetic examples, tests and documentation belong in this repository.

## License and provenance

MIT; see `LICENSE`. This repository's implementation and tests were newly authored for this extraction, using standard PowerShell/.NET APIs. No source, binaries or dependencies from third-party projects are bundled. Historical private diagnostic scripts supplied behavioral requirements, not public fixtures. No claim is made to license Windows, PowerShell or .NET themselves.
