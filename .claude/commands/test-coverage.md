---
description: Run CLI tests with coverage, enforce per-package thresholds
argument-hint: "[package]   # optional; defaults to ./..."
---

Run the CLI test suite with coverage from `cli/`.

Steps:

1. Run `go test -count=1 -coverprofile=/tmp/cradar-cover.out ${ARGUMENTS:-./...}`.
2. Run `go tool cover -func=/tmp/cradar-cover.out | tail -30` to get
   per-package + total coverage.
3. Enforce thresholds (report but do not modify code):
   - `cli/internal/rulefilter` ≥ 85%
   - `cli/internal/baseline`   ≥ 85%
   - `cli/internal/explain`    ≥ 80%
   - `cli/internal/scannerinit` ≥ 70%
   - Overall CLI               ≥ 60%

Pre-existing failure baseline — these are known flaky or
missing-fixture failures and should NOT be treated as regressions:

- `TestAdminResetPasswordOutput`
- `TestParsePasses`
- `TestScanCommand_TextOutput`
- `TestCertificateParsing` (missing fixture)
- `TestPEMDetection` (missing fixture)
- `TestScanDirUniversalScannersRunOnAllFiles` (flaky under parallel
  package testing)

Report:

- `PASS` / `FAIL` counts.
- Any new failure not in the baseline list (fail the check if any).
- Per-threshold package summary: `<pkg>: <pct>% (threshold <X>%) OK/FAIL`.

Do NOT edit files unless the user asks.
