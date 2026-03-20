# SonarQube Integration

CipherRadar exports cryptographic findings in SonarQube Generic Issue Data format, allowing direct import into SonarQube without a custom plugin. SARIF import is also supported as an alternative.

## Generic Issue Export

Generate a SonarQube-compatible report from any scanned codebase:

```bash
cradar scan --path /path/to/project --format sonarqube-generic -o cradar-sonarqube.json
```

The output file follows the [SonarQube Generic Issue Import](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/) specification. Each cryptographic finding is mapped to a SonarQube issue with:

- **engineId**: `cipherradar`
- **ruleId**: the CipherRadar detection rule ID (e.g. `cbom-java-weak-hash`)
- **severity**: mapped from CipherRadar severity to SonarQube severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
- **type**: `VULNERABILITY` for quantum-vulnerable findings, `CODE_SMELL` for informational
- **primaryLocation**: source file, line, and description

## SonarQube Scanner Configuration

Add the report path to your `sonar-project.properties`:

```properties
# Import CipherRadar findings as external issues
sonar.externalIssuesReportPaths=cradar-sonarqube.json
```

If you generate multiple reports (e.g. per module), use a comma-separated list:

```properties
sonar.externalIssuesReportPaths=module-a/cradar-sonarqube.json,module-b/cradar-sonarqube.json
```

## SARIF Import (Alternative)

SonarQube Developer Edition and above support SARIF import. CipherRadar can export SARIF 2.1.0:

```bash
cradar scan --path /path/to/project --format sarif -o cradar-sarif.json
```

Configure the SARIF report path in `sonar-project.properties`:

```properties
sonar.sarifReportPaths=cradar-sarif.json
```

SARIF import provides richer metadata than the generic format (CWE references, help URIs, markdown descriptions) but requires SonarQube Developer Edition or higher. The generic format works with all SonarQube editions including Community.

## Example CI Pipeline (GitHub Actions + SonarQube)

```yaml
name: CipherRadar + SonarQube

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for SonarQube blame data

      - name: Install CipherRadar CLI
        run: |
          curl -sSL https://get.cipherradar.io | sh
          cbom install-tools

      - name: Run CipherRadar scan (generic format)
        run: |
          cradar scan \
            --path . \
            --format sonarqube-generic \
            -o cradar-sonarqube.json

      - name: Run CipherRadar scan (SARIF alternative)
        run: |
          cradar scan \
            --path . \
            --format sarif \
            -o cradar-sarif.json

      - name: SonarQube Scan
        uses: SonarSource/sonarqube-scan-action@v3
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.externalIssuesReportPaths=cradar-sonarqube.json
```

To use SARIF instead, replace the last argument with:

```yaml
          args: >
            -Dsonar.sarifReportPaths=cradar-sarif.json
```

## Where Findings Appear in SonarQube

<!-- Screenshot placeholder: SonarQube Issues view showing CipherRadar external issues -->
**[Screenshot: SonarQube Issues List]** — After import, CipherRadar findings appear in the Issues tab with the `cipherradar` engine badge. Filter by `Tag: cbom` or `Rule: external_cipherradar:*` to isolate cryptographic findings.

<!-- Screenshot placeholder: SonarQube Issue detail view for a CipherRadar finding -->
**[Screenshot: Issue Detail View]** — Each finding shows the source file, line number, severity, and CipherRadar-specific description including the affected algorithm, quantum readiness status, and remediation guidance.

<!-- Screenshot placeholder: SonarQube Security Hotspots showing crypto findings -->
**[Screenshot: Security Hotspots]** — When using SARIF import, findings with CWE mappings also appear in the Security Hotspots view, grouped by CWE category (e.g. CWE-327: Use of a Broken or Risky Cryptographic Algorithm).

## Severity Mapping

| CipherRadar Severity | SonarQube Generic Severity | SARIF Level   |
|-----------------------|---------------------------|---------------|
| critical              | BLOCKER                   | error         |
| high                  | CRITICAL                  | error         |
| medium                | MAJOR                     | warning       |
| low                   | MINOR                     | note          |
| info                  | INFO                      | note          |

## Limitations (Phase 3)

- **Generic format only** — the full SonarQube plugin with native rule definitions, custom quality profiles, and quality gate conditions is planned for Phase 4.
- External issues imported via the generic format cannot block quality gates. Use the SARIF import path on Developer Edition if quality gate enforcement is required.
- SonarQube external issues are read-only and cannot be transitioned (e.g. marked as won't fix) within SonarQube itself. Use the CipherRadar dashboard for suppression management.
