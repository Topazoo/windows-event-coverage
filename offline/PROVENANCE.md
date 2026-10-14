# Provenance and distribution scope

The implementation, CLI, documentation, examples and test generators in this package are newly authored for this offline extraction. The reviewed private engineering work supplied behavioral requirements: precise UTC boundaries, explicit coverage errors, saved-analysis parsing, WER identity handling, module metadata, noncausal reporting and integrity receipts. No private source files or diagnostic outputs were copied into this directory.

Behavioral source families were the event analysis/finalization scripts, saved debugger analysis reader, module-metadata reader, selected-WER readers and evidence-preservation routines. Their hard-coded paths, identity checks, protected-read wrappers, live discovery and mutable checkpoints are intentionally not part of this implementation. No code from the inaccessible separate diagnostics toolkit was accessed or incorporated.

Dependencies are Python's standard library. No debugger, symbol files, Microsoft SDK header/source, third-party parser, downloaded code or binary is bundled. The MINIDUMP fields and Windows text conventions are interoperability formats, not copied third-party implementations. There are no inherited third-party notices identified in this newly written package and no concrete third-party license conflict found. Python, Windows and external tools retain their own licenses.

All examples are invented. Test minidumps are assembled with Python struct in temporary directories; no real dumps or logs are fixtures. The MIT grant covers this package's original code and documentation. It does not grant rights in any evidence a user later supplies.

Proposed public scope is only this package's source, tests, text examples, documentation, packaging metadata and license. Keep private inputs, generated outputs, caches, local verification receipts containing filesystem paths, archives and diagnostic data out of publication. No remote or public release is created by the package.
