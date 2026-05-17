# ADR-036: Structured Logging, Redaction Defaults, and Exit-Code Contract

**Status:** Accepted
**Date:** 2026-04-15
**Decision Makers:** Development team
**Phase:** CLI improvements (item 2: structured logging + validator enrichment)

## Context

The CLI had no logging library (zero hits for `slog|zerolog|logrus` across
`cli/`). The `--verbose` flag was declared in `root.go` but never read.
When a scan failed — schema validation, a push error, an unexpected rule
behaviour — users had no structured record to pipe into Claude or attach
to an issue. Stderr carried a fragmented mix of human-friendly summaries
and ad-hoc `fmt.Fprintf` debug lines that was neither greppable by humans
nor machine-parseable.

Three related pain points surfaced together:

1. **Schema validator is opaque.** The 37 CycloneDX 1.7 enum failures in
   `docs/benchmark/TODO-SCHEMA-VALIDATION.md` showed only "does not match
   schema" — no hint of what the allowed values were.
2. **`--fail-on` stopped at the first offender.** On a repo with dozens of
   high-severity findings, users saw only one and had to re-run to find
   the rest.
3. **`os.Exit` in `policy.go` skipped deferred cleanup.** Temp dirs and
   open log files leaked on the policy-failure path.

## Decision

### 1. Structured logging via stdlib `log/slog`

A new `cli/pkg/log` package wraps `slog` with no third-party dependency.
Each `cradar` process writes to:

```
~/.cradar/logs/cradar-<YYYYMMDD-HHMMSS>-<pid>.log.jsonl
```

Records carry a per-run `runID` attribute so lines from one process can be
grepped out of an interleaved log directory. Level is controlled by the
new persistent flags on `rootCmd`:

- `--verbose` — info + verbose events.
- `--debug` — everything including trace events.
- `--quiet` — error only.
- `--log-file PATH` — override the default sink (for CI pipelines).
- `--log-format json|text` — json default; text for humans tailing live.
- `--log-include-source` — opt-in inclusion of source snippets.

On any non-zero exit, `cmd.Execute` prints `cradar: see log at <path>` to
stderr so the user has a one-line pointer to pipe into Claude.

### 2. Redaction defaults

The logger is privacy-safe by default:

- Paths are relativised against the scan root via `Logger.RedactPath`.
  Paths outside the root are preserved verbatim (rewriting them would be
  misleading).
- Matched source snippets are **never** logged unless
  `--log-include-source` is explicitly passed.
- Environment values are never logged by the package — call sites must
  not pass env values as structured attributes.

Two dedicated tests
(`TestRedaction_LogNeverContainsAbsolutePath`,
`TestRedaction_OutsideRootIsPreserved`) exercise the full write path and
fail loudly if a future change leaks absolute paths into log files.

### 3. Retention

The logger prunes `cradar-*.log.jsonl` entries beyond the newest 10 on
startup. The cap is informational — no external log rotation tooling is
required. Prune failures are swallowed so log rotation can never prevent
the CLI from running on a read-only or full filesystem.

### 4. Schema validator enrichment

`validation.collectErrors` walks the `jsonschema.ValidationError.Causes`
tree and emits only leaf errors (nodes with no `Causes`). Each leaf
carries:

- `Path` — JSON Pointer to the offending instance location.
- `Keyword` — `enum`, `const`, `type`, `required`, `format`, or
  `additionalProperties`.
- `Expected` — allowed values (enum, type, required) or single expected
  (const, format).
- `Actual` — rendered offending value.

The `scan.go` stderr line now reads:

```
expected one of [aes, rsa, ecdsa, ...]; got concatkdf
```

and the same information is recorded as structured log attributes so it
can be machine-parsed.

### 5. Aggregated `--fail-on`

`checkFailOn` now collects every offender, counts by severity, and
returns a single grouped error listing up to 5 concrete examples plus a
"N more" tail. The pre-existing behaviour of stopping at the first hit is
gone — large codebases get the full picture in a single run.

### 6. Exit-code contract

`cli/internal/cmd/exitcode.go` introduces a typed `ExitError` with an
`ExitCode` helper. `main.go` maps the final error to an exit code:

| Code | Meaning | Used by |
|-----:|---------|---------|
| 0 | Clean — no findings at or above `--fail-on` | default |
| 1 | Findings at or above `--fail-on` threshold; generic runtime error | `checkFailOn`, cobra default |
| 2 | Warnings only | policy warn path |
| 3 | Configuration / schema error | bad `--fail-on` severity, schema validation failure |
| 4 | Required external tool missing | reserved for OpenGrep / YARA-X |

`os.Exit` calls in subcommands are removed — they return `ExitError`
instead. This restores deferred cleanup and lets `cmd.Execute` flush the
log file on failure.

## Consequences

### Positive

- Users can pipe `~/.cradar/logs/*.jsonl` into Claude to debug failures
  with structured context.
- The 37 CycloneDX 1.7 enum errors become actionable.
- `--verbose` does something.
- Policy-failure path runs deferred cleanup.
- Exit codes are documented and enforceable in CI pipelines.

### Negative

- Slight binary size increase from pulling in `log/slog` transitively
  (already part of stdlib; negligible).
- Disk usage: up to 10 log files per user under `~/.cradar/logs/`.
  Retention guards this; worst case is bounded by the number of scans a
  user runs.

### Neutral

- The `cbom` legacy alias inherits the same logging surface — no
  per-binary divergence.
- `.cradar.yml` may gain a `logging:` block in a future ADR if users want
  per-project defaults beyond CLI flags. Not done yet to keep item 2
  focused.

## Alternatives considered

- **zerolog / zap** — rejected. Stdlib `slog` is sufficient and avoids
  adding a direct dependency for a CLI whose logging needs are modest.
- **Stderr-only logging** — rejected. Stderr is the UX channel for humans
  watching the scan run; it must not be polluted with structured debug
  records. File + stderr split keeps both consumers happy.
- **Single exit code for all failures** — rejected. CI pipelines need to
  distinguish "findings" from "the tool itself crashed" from "OpenGrep is
  not installed" to route alerts correctly.
- **Concurrent-scan log interleaving via per-scan subdir** — deferred.
  No user has reported running parallel scans in one process yet; adding
  it now would complicate the file-handle lifecycle with no payoff.

## References

- `cli/pkg/log/log.go` — logger package.
- `cli/internal/cmd/exitcode.go` — typed exit-code contract.
- `cli/internal/validation/validator.go` — enriched `collectErrors`.
- `cli/internal/cmd/scan.go` — `checkFailOn` aggregation,
  `formatUserMessage` enum-hint formatting.
- `docs/cli-improvements-plan.md` — item 2 (structured logging +
  validator enrichment).
