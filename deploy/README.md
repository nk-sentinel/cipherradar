# CipherRadar CI/CD Integration

Run CipherRadar CBOM scans automatically in your CI/CD pipelines to detect cryptographic assets and enforce cryptographic policies on every commit.

## GitHub Actions

### Quick Start

Add the following to `.github/workflows/cbom-scan.yml` in your repository:

```yaml
name: CBOM Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  cbom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run CipherRadar Scan
        uses: ./deploy/github-action
        with:
          format: cyclonedx-json
          output: cbom.json
          passes: '1'
          upload-artifact: 'true'
```

### Inputs

| Input             | Description                                              | Default            |
|-------------------|----------------------------------------------------------|--------------------|
| `path`            | Path to scan                                             | `.`                |
| `format`          | Output format (`cyclonedx-json`, `sarif`, `text`, `pdf`) | `cyclonedx-json`   |
| `output`          | Output file name                                         | `cbom.json`        |
| `passes`          | Scan passes to run (`1`, `2`, `3`)                       | `1`                |
| `policy`          | Path to policy file for enforcement                      | (none)             |
| `fail-on`         | Minimum severity to fail the build                       | (none)             |
| `upload-artifact` | Upload CBOM as a build artifact                          | `true`             |
| `upload-sarif`    | Upload SARIF to GitHub Code Scanning                     | `false`            |

### Outputs

| Output           | Description                   |
|------------------|-------------------------------|
| `findings-count` | Total number of findings      |
| `critical-count` | Number of critical findings   |
| `high-count`     | Number of high findings       |

### SARIF Upload (GitHub Code Scanning)

To surface findings in the GitHub Security tab, enable the `upload-sarif` input and set `format` to `sarif`:

```yaml
- name: Run CipherRadar Scan
  uses: ./deploy/github-action
  with:
    format: sarif
    output: cbom.sarif
    upload-sarif: 'true'
```

This requires GitHub Advanced Security to be enabled on the repository.

### Policy Enforcement

Fail the build when findings exceed a severity threshold:

```yaml
- name: Run CipherRadar Scan
  uses: ./deploy/github-action
  with:
    policy: policy.cbom.yml
    fail-on: high
```

The `cbom policy check` command will exit non-zero if any findings at or above the specified severity are detected, causing the workflow to fail.

---

## GitLab CI

### Quick Start

Add the following to your `.gitlab-ci.yml`:

```yaml
include:
  - project: 'nk-sentinel/cipherradar'
    ref: main
    file: 'deploy/gitlab-ci/cbom-scan.gitlab-ci.yml'
```

For local testing within the CipherRadar monorepo:

```yaml
include:
  - local: 'deploy/gitlab-ci/cbom-scan.gitlab-ci.yml'
```

### Variables

Override these CI/CD variables to customize the scan:

| Variable            | Description                                              | Default            |
|---------------------|----------------------------------------------------------|--------------------|
| `CBOM_FORMAT`       | Output format (`cyclonedx-json`, `sarif`, `text`, `pdf`) | `cyclonedx-json`   |
| `CBOM_OUTPUT`       | Output file name                                         | `cbom.json`        |
| `CBOM_PASSES`       | Scan passes to run (`1`, `2`, `3`)                       | `1`                |
| `CBOM_POLICY`       | Path to policy file for enforcement                      | (none)             |
| `CBOM_FAIL_ON`      | Minimum severity to fail the pipeline                    | (none)             |
| `CBOM_SARIF_OUTPUT` | SARIF output file name                                   | `cbom.sarif`       |

### SARIF and GitLab Security Dashboard

The template automatically generates a SARIF report and attaches it as a `sast` artifact report. This integrates with the GitLab Security Dashboard, surfacing findings directly in merge requests.

### Policy Enforcement

Set the `CBOM_POLICY` and `CBOM_FAIL_ON` variables to enable policy checks:

```yaml
variables:
  CBOM_POLICY: "policy.cbom.yml"
  CBOM_FAIL_ON: "high"
```

The pipeline will fail if any findings meet or exceed the specified severity.

### Pipeline Rules

By default, the `cbom-scan` job runs on:
- Merge request pipelines
- Commits to the default branch

Override the `rules` key in your `.gitlab-ci.yml` to customize when the job runs.

---

## Scan Passes

CipherRadar supports multiple scan passes with increasing depth:

- **Pass 1** -- Static pattern matching (fastest, default)
- **Pass 2** -- AST-level analysis
- **Pass 3** -- Deep cross-file data-flow analysis (slowest, most thorough)

Use `passes: '1,2'` (GitHub) or `CBOM_PASSES: "1,2"` (GitLab) to combine passes.
