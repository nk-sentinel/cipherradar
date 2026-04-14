---
description: Run Go vet + build on the CLI and report failures
argument-hint: "[package]   # optional; defaults to ./..."
---

Run Go static analysis on the CLI package(s). Use the Bash tool from
inside `cli/` to run, in parallel:

- `go build ${ARGUMENTS:-./...}` — surfaces compile errors
- `go vet ${ARGUMENTS:-./...}` — standard vet checks
- `gofmt -l ${ARGUMENTS:-.}` — list any unformatted files (fail if output
  is non-empty)

If `golangci-lint` is on PATH, run `golangci-lint run ${ARGUMENTS:-./...}`
additionally. Otherwise skip silently — golangci-lint is optional for
local dev.

Report:
- One line per tool: `<tool>: OK` or the first few error lines.
- Exit non-zero summary if any tool reported errors.

Do NOT edit files — this is a read-only diagnostic command. If the user
wants a fix, they will ask explicitly.
