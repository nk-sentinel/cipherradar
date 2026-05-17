# ADR-037: Multi-Output Sinks, Extension Dispatch, and TTY-Aware Defaults

**Status:** Accepted
**Date:** 2026-04-15
**Decision Makers:** Development team
**Phase:** CLI improvements (item 3: multi-output formats)

## Context

`cradar scan`'s `--format` / `--output` pair was single-valued: producing
CycloneDX JSON, a SARIF file, and a PDF for the same codebase meant
running the scanner three times. Three concrete problems compounded:

1. **Single `-o`.** Passing `-o` twice silently kept only the last value.
2. **`text` was misleading.** Users reached for `--format text`
   expecting a row-per-finding listing but got a dashboard summary.
3. **Defaults were inconsistent and stale.** `scan` defaulted to
   `cyclonedx-json`, `report` to `pdf`, `diff` to `text`; the
   `default_format` key in `.cradar.yml` was parsed but never read; the
   `--format` help text listed four formats while the writer registry
   held five.

## Decision

### 1. Repeatable `--output` with extension dispatch

`--output` (`-o`) becomes a `StringSlice`: one scan, many artifacts.

```bash
cradar scan ./app -o cbom.json -o cbom.sarif -o cbom.pdf
```

Each destination's format is inferred from its extension via the new
`output.FormatFromPath`:

| Extension                                            | Format              |
|------------------------------------------------------|---------------------|
| `.json`, `.cbom.json`, `.cdx.json`, `.cyclonedx.json`| `cyclonedx-json`    |
| `.sonar.json`                                        | `sonarqube-generic` |
| `.sarif`                                             | `sarif`             |
| `.pdf`                                               | `pdf`               |
| `.txt`, `.text`                                      | `text`              |

`.sonar.json` is evaluated before `.json` so SonarQube reports don't
silently land in the CycloneDX lane.

`--format` still works when writing to stdout (no `-o`) or when there is
exactly one `-o` target. With multiple outputs it's ambiguous; we emit a
warning and ignore the flag.

### 2. `output.ResolveOutputFormat` precedence chain

```
explicit --format  >  file-extension dispatch  >  .cradar.yml default_format  >  built-in fallback
```

Applied uniformly in `scan` and `report`. `.cradar.yml`'s
`default_format` key finally takes effect.

### 3. Row-level `table` writer

A new `TableWriter` fills the gap users kept hitting with `--format
text`: one line per finding, tab-aligned columns
(`SEVERITY / RULE / LOCATION / NAME`), sorted critical-first for triage.

`text` stays the dashboard summary. `table` is the row view. Both are
selectable via `--format`; `table` has no extension dispatch because it
is a stdout display format, not a persisted artifact.

### 4. TTY-aware stdout fallback

When no `-o`, no `--format`, and no `default_format` apply,
`output.DefaultStdoutFormat()` picks:

- **TTY** → `text` (human reading the terminal)
- **pipe / redirect** → `cyclonedx-json` (`scan > out.json` works)

`NO_COLOR` / `FORCE_COLOR` intentionally don't influence this choice —
they control coloring, not format.

### 5. Exit codes for format errors

`output.ValidateFormat` is called before `WriterFactory` in both
`scan.go` and `report.go`; unknown formats now exit with `ExitConfig`
(3) per ADR-036 rather than bubbling up a generic error.

## Consequences

### Positive

- One scan produces every artifact CI needs.
- `text` vs. `table` split removes a long-standing expectation mismatch.
- `.cradar.yml` `default_format` is finally honored.
- Piped stdout is machine-readable by default; interactive stdout is
  human-readable by default.
- Format errors integrate with the typed exit-code contract.

### Negative

- Scripts that relied on `-o a.json -o b.json` silently keeping only
  `b.json` now produce both files. This is deliberate and documented in
  the commit that introduced `StringSlice`.

### Neutral

- `diff` stays out of the shared writer registry. Its output operates on
  `diff.Result` rather than `ScanResult`, and the `text` / `json` split
  there is intentional — unifying would either widen the Writer
  interface or require a coerce layer, both of which outweigh the
  payoff. Revisit if a diff consumer asks for SARIF.

## Alternatives considered

- **Fold diff into the shared registry.** Rejected for the shape reason
  above.
- **Keep single `-o` and add `--outputs=a,b`.** Rejected; `-o file1 -o
  file2` is the idiomatic Cobra/pflag pattern and matches what users
  already reach for.
- **Make `text` itself row-level when `--verbose` is set.** Rejected;
  overloading `text` reintroduces the expectation mismatch rather than
  solving it. A distinct writer is cheaper to teach.

## References

- `cli/internal/output/dispatch.go` — `FormatFromPath`,
  `ResolveOutputFormat`, `ValidateFormat`, `DefaultStdoutFormat`.
- `cli/internal/output/table.go` — row-level writer.
- `cli/internal/cmd/scan.go` — repeatable `--output` wiring,
  `writeOutputs` loop, TTY fallback application.
- `cli/internal/cmd/report.go` — parity with scan's precedence chain.
- `docs/cli-improvements-plan.md` — item 3 (multi-output formats).
