# Output Formats

`cradar` writes findings in several formats. Pick the one that matches the consumer — a CBOM
artifact for archival, SARIF for code-scanning dashboards, PDF for executives, SonarQube
generic-issue JSON for SonarQube, or a terminal-friendly summary for humans.

## Selecting a format

The format used for each destination is resolved in this order:

1. `--format` flag (explicit override; only honored on stdout or when there is exactly one `--output`).
2. File extension dispatch (`out.sarif` → SARIF, `out.pdf` → PDF, etc.).
3. `default_format` in `.cradar.yml`.
4. Built-in fallback — `cyclonedx-json` for files, TTY-aware for stdout.

`--output` is repeatable on `cradar scan`. Each path is dispatched independently, so a single
scan can emit a CBOM, a SARIF report, and a PDF in one pass:

```bash
cradar scan ./service \
  -o cbom.json \
  -o issues.sarif \
  -o report.pdf
```

When `--format` is set with multiple `--output` paths, the flag is ambiguous and is ignored
with a warning printed on stderr.

## Extension dispatch

| Extension                                            | Format              |
|------------------------------------------------------|---------------------|
| `.cbom.json`, `.cdx.json`, `.cyclonedx.json`         | `cyclonedx-json`    |
| `.json`                                              | `cyclonedx-json`    |
| `.sonar.json`                                        | `sonarqube-generic` |
| `.sarif`                                             | `sarif`             |
| `.pdf`                                               | `pdf`               |
| `.txt`, `.text`                                      | `text`              |

`.sonar.json` is checked before `.json`, so a SonarQube report does not silently land in the
CycloneDX lane. Extensions are matched case-insensitively.

## TTY-aware stdout default

When stdout has no extension to dispatch on and `--format` is unset:

- **Interactive terminal** — defaults to `text` (the human-friendly dashboard summary).
- **Pipe or redirect** — defaults to `cyclonedx-json`, so `cradar scan ./app > cbom.json`
  produces a valid CBOM without extra flags.

`NO_COLOR` and `FORCE_COLOR` control color output but not format dispatch.

---

## cyclonedx-json (default for files)

The canonical CBOM artifact: CycloneDX 1.7 JSON. Pass to `--validate` to check it against the
embedded schema.

- File extensions: `.json`, `.cbom.json`, `.cdx.json`, `.cyclonedx.json`.
- Best for: archival, ingestion into the portal, downstream tools that consume CycloneDX,
  signing with `cosign`, and the `cradar diff` / `cradar policy check` workflows.

Sample (truncated):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-01T12:00:00Z",
    "tools": [{ "vendor": "CipherRadar", "name": "cradar", "version": "..." }]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "alg-rsa-pkcs1v15",
      "name": "RSA-PKCS1v15",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "padding": "pkcs1v15",
          "executionEnvironment": "software-plain-ram"
        }
      }
    }
  ]
}
```

---

## sarif

Static Analysis Results Interchange Format. Built for code-scanning dashboards — GitHub
Advanced Security, GitLab SAST, Azure DevOps, and most modern IDEs.

- File extension: `.sarif`.
- Best for: pull-request annotations, GitHub code-scanning upload, IDE inline diagnostics.

Sample (truncated):

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": { "name": "cradar", "version": "...", "informationUri": "..." }
      },
      "results": [
        {
          "ruleId": "cbom-python-weak-hash",
          "level": "warning",
          "message": { "text": "MD5 used as cryptographic hash" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/auth.py" },
                "region": { "startLine": 42, "startColumn": 9 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## text

Terminal-friendly dashboard summary. Aggregates findings by severity, language, and rule, with
ANSI colors when stdout is a TTY (and `NO_COLOR` is unset).

- File extensions: `.txt`, `.text`. Usually used on stdout.
- Best for: humans reading the terminal output of a local scan.

Sample (truncated, colors stripped):

```
CipherRadar Scan Summary
========================

Target:     ./service
Duration:   2.4s
Findings:   17

By severity:
  CRITICAL  2
  HIGH      5
  MEDIUM    7
  LOW       3

By category:
  inventory  12
  security    5

Top rules:
  cbom-python-weak-hash               4   high
  cbom-java-rsa-keysize               3   medium
  cbom-go-tls-min-version             2   high
```

---

## table

Row-per-finding, tab-aligned view. Fills the gap between the dashboard `text` summary and the
machine-readable formats: one line per finding, sorted critical-first, ready for piping into
`grep`, `awk`, or `column -t`.

- No extension dispatch — this is a stdout display format. Select with `--format table`.
- Best for: scripting, quick triage, or piping into other Unix tools.

Sample:

```
SEVERITY  RULE                            LOCATION             NAME
critical  cbom-python-weak-hash           src/auth.py:42       MD5 used as cryptographic hash
high      cbom-java-rsa-keysize           src/Crypto.java:88   RSA key size below 2048 bits
medium    cbom-go-tls-min-version         server/tls.go:14     TLS minimum version is 1.0
```

---

## pdf

Executive-style PDF report — summary, charts, and the top findings, suitable for handing to a
security review board.

- File extension: `.pdf`.
- Best for: governance reports, audit packages, anything that lives in a Confluence page.

The default for `cradar report` is `pdf`, so:

```bash
cradar report cbom.json -o cbom-executive.pdf
```

works without any flag tuning.

---

## sonarqube-generic

SonarQube generic issue import format. Each finding becomes an issue with a rule key, severity,
location, and message that the SonarQube generic-issue plugin understands.

- File extension: `.sonar.json`.
- Best for: SonarQube projects that want CipherRadar findings in the same dashboard as their
  static analysis.

Sample (truncated):

```json
{
  "issues": [
    {
      "engineId": "cradar",
      "ruleId": "cbom-python-weak-hash",
      "severity": "MAJOR",
      "type": "VULNERABILITY",
      "primaryLocation": {
        "message": "MD5 used as cryptographic hash",
        "filePath": "src/auth.py",
        "textRange": { "startLine": 42 }
      }
    }
  ]
}
```

Upload with `sonar-scanner` using `sonar.externalIssuesReportPaths=issues.sonar.json`.
