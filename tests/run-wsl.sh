#!/usr/bin/env bash
# Run from an existing WSL installation. This script installs nothing.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo"
git diff --cached --check
python3 - <<'PY'
import json
from pathlib import Path

for path in sorted(Path('examples').glob('*.json')):
    with path.open(encoding='utf-8') as source:
        json.load(source)
    print(f'PASS JSON parse: {path}')
PY

runtime=${1:-pwsh}
if ! command -v "$runtime" >/dev/null 2>&1; then
    printf '%s\n' 'No PowerShell runtime found. Install/use an authorized Linux PowerShell runtime,' \
        'or explicitly pass an existing Windows pwsh.exe path for WSL interoperability tests.' >&2
    exit 3
fi
case "$runtime" in
    *.exe)
        printf '%s\n' 'Runtime: Windows PowerShell via WSL interoperability (not native Linux).'
        test_file=$(wslpath -w "$repo/tests/Run-Tests.ps1")
        ;;
    *)
        printf '%s\n' 'Runtime: native PowerShell.'
        test_file="$repo/tests/Run-Tests.ps1"
        ;;
esac
"$runtime" -NoProfile -File "$test_file"
