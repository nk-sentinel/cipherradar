# CipherRadar CI/CD Integration

Run CipherRadar scans automatically in your CI/CD pipelines to detect cryptographic assets and enforce cryptographic policies on every commit.

> **Note:** The CLI binary was renamed from `cbom` to `cradar` per ADR-024. The GitHub Action is now `cradar-action`. `cbom` remains as a legacy alias during Phase 3.

## GitHub Actions

### Quick Start

Add the following to `.github/workflows/cradar-scan.yml` in your repository:

```yaml
name: CipherRadar Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  cradar-scan:
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
    policy: policy.cradar.yml
    fail-on: high
```

The `cradar policy check` command will exit non-zero if any findings at or above the specified severity are detected, causing the workflow to fail.

---

## GitLab CI

### Quick Start

Add the following to your `.gitlab-ci.yml`:

```yaml
include:
  - project: 'nk-sentinel/cipherradar'
    ref: main
    file: 'deploy/gitlab-ci/cradar-scan.gitlab-ci.yml'
```

For local testing within the CipherRadar monorepo:

```yaml
include:
  - local: 'deploy/gitlab-ci/cradar-scan.gitlab-ci.yml'
```

### Variables

Override these CI/CD variables to customize the scan:

| Variable              | Description                                              | Default            |
|-----------------------|----------------------------------------------------------|--------------------|
| `CRADAR_FORMAT`       | Output format (`cyclonedx-json`, `sarif`, `text`, `pdf`) | `cyclonedx-json`   |
| `CRADAR_OUTPUT`       | Output file name                                         | `cbom.json`        |
| `CRADAR_PASSES`       | Scan passes to run (`1`, `2`, `3`)                       | `1`                |
| `CRADAR_POLICY`       | Path to policy file for enforcement                      | (none)             |
| `CRADAR_FAIL_ON`      | Minimum severity to fail the pipeline                    | (none)             |
| `CRADAR_SARIF_OUTPUT` | SARIF output file name                                   | `cbom.sarif`       |

### SARIF and GitLab Security Dashboard

The template automatically generates a SARIF report and attaches it as a `sast` artifact report. This integrates with the GitLab Security Dashboard, surfacing findings directly in merge requests.

### Policy Enforcement

Set the `CRADAR_POLICY` and `CRADAR_FAIL_ON` variables to enable policy checks:

```yaml
variables:
  CRADAR_POLICY: "policy.cradar.yml"
  CRADAR_FAIL_ON: "high"
```

The pipeline will fail if any findings meet or exceed the specified severity.

### Pipeline Rules

By default, the `cradar-scan` job runs on:
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

---

## Releasing

CipherRadar CLI releases are managed by [GoReleaser v2](https://goreleaser.com/) and produce two binary flavors per platform (darwin/linux, amd64/arm64).

### Binary Flavors

| Artifact       | Size       | Description                                              |
|----------------|------------|----------------------------------------------------------|
| `cradar`       | ~15 MB     | Lightweight binary. Users run `cradar install-tools` to download OpenGrep separately. |
| `cradar-full`  | ~80-100 MB | Same binary bundled with OpenGrep in the archive. For air-gapped environments. |

Both flavors produce identical `cradar` binaries — the only difference is whether the OpenGrep executable is included alongside it in the archive.

> **Note:** Binary renamed from `cbom`/`cbom-full` to `cradar`/`cradar-full` per ADR-024. `cbom` is available as a legacy alias during Phase 3.

### How It Works

1. **GoReleaser config** (`cli/.goreleaser.yml`) defines two builds (`cradar` and `cradar-full`) and two archive templates. Both builds compile the same `cmd/cradar` entry point with version/commit/date injected via ldflags.
2. **Release workflow** (`deploy/github-action/release.yml`) runs on any `v*` tag push. It downloads OpenGrep binaries for each platform into `dist/opengrep-<os>-<arch>/`, then invokes GoReleaser to build, archive, and create a draft GitHub release.

### Creating a Release

```bash
# Tag the release
git tag v0.1.0
git push origin v0.1.0
```

The release workflow triggers automatically. It creates a **draft** release on GitHub with all artifacts attached. Review the draft and publish when ready.

### Produced Artifacts

For each release, the following artifacts are uploaded:

- `cradar_<version>_<os>_<arch>.tar.gz` — lightweight archive (4 platform variants)
- `cradar-full_<version>_<os>_<arch>.tar.gz` — full archive with OpenGrep (4 platform variants)
- `checksums.txt` — SHA-256 checksums for all archives

### Version Information

Version, commit, and build date are injected at build time via ldflags into `cli/internal/cmd/version.go`. Run `cradar version` to see the build metadata.
