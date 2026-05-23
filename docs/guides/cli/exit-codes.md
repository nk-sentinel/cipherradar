# Exit Codes

`cradar` follows a stable exit-code contract so CI pipelines can distinguish "the scanner ran
and found something" from "the scanner could not run". The contract is part of the public CLI
surface — it does not change without a major version bump.

## Contract

| Code | Constant         | Meaning                                                                                  |
|------|------------------|------------------------------------------------------------------------------------------|
| `0`  | `ExitOK`         | Clean run. No findings at or above `--fail-on` (or no `--fail-on` set).                  |
| `1`  | `ExitFindings`   | Findings or policy violations at or above the `--fail-on` threshold. Also generic runtime errors. |
| `2`  | `ExitWarnings`   | Warnings only. Used by `cradar policy check` when every violation is below `--fail-on`.  |
| `3`  | `ExitConfig`     | Configuration error. Invalid flag, missing file, malformed YAML, schema validation failure, bad path. |
| `4`  | `ExitToolMissing`| A required external tool (OpenGrep, YARA-X) was not installed and the run cannot continue. |

On any non-zero exit, `cradar` prints `cradar: see log at <path>` to stderr so the structured
log is easy to attach to a bug report.

## Notes by code

### `0` — clean

The scan completed and either there was no `--fail-on` set, or no finding reached the threshold.

### `1` — findings or generic failure

Returned in three scenarios:

- `cradar scan` finished but at least one finding meets or exceeds `--fail-on`.
- `cradar policy check` reports a `FAIL` for one or more rules at or above `--fail-on`.
- Any unexpected runtime error that is not classified above (network failure during `--push`,
  unreadable input file, etc.) — these wrap the underlying error into the default code.

### `2` — warnings only

`cradar policy check` returns this when every policy violation falls strictly below
`--fail-on`. The pipeline keeps going but the step can be surfaced as a warning.

### `3` — configuration

The scan never produced a verdict because the run was misconfigured. Common causes:

- Scan path does not exist or is not a directory.
- Invalid `--fail-on` severity (typo).
- Invalid `--category` value.
- Unsupported `--format` value.
- CycloneDX schema validation failure when `--validate` is on.
- `--policy` file is missing or unparseable.
- `cradar init` would overwrite an existing file and `--force` was not passed.

### `4` — external tool missing

Pass 2 (OpenGrep) was explicitly requested via `--deep` or `--passes` and OpenGrep was not
installed. Run `cradar install-tools` or switch to the `cradar-full` distribution. When pass 2
is only running because it is in the default set, the missing tool degrades to a stderr warning
and pass 2 is skipped — the scan still returns 0.

## In CI

A pragmatic CI gate that lets findings fail the build, lets warnings show up as a warning, and
treats configuration / tool-missing errors as build errors:

```bash
set +e
cradar scan ./service --fail-on high -o cbom.json
status=$?
set -e

case "$status" in
  0)   echo "no findings at or above the threshold" ;;
  1)   echo "findings at or above --fail-on; failing the build" ; exit 1 ;;
  2)   echo "warnings only" ;;
  3)   echo "configuration error" ; exit 1 ;;
  4)   echo "external tool missing; install with 'cradar install-tools'" ; exit 1 ;;
  *)   echo "unexpected exit code $status" ; exit 1 ;;
esac
```

GitHub Actions equivalent — surface code `2` as a warning annotation but keep the job green:

```yaml
- name: CipherRadar scan
  id: cradar
  continue-on-error: true
  run: cradar scan ./service --fail-on high -o cbom.json

- name: Fail on real findings
  if: steps.cradar.outcome == 'failure' && steps.cradar.conclusion != 'success'
  run: exit 1
```
