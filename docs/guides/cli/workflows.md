# Workflows

Common `cradar` usage patterns. Each recipe is self-contained — copy the commands, adjust the
paths, ship it.

## 1. CI gate

Block pull requests that introduce a high-or-above cryptographic finding, but always archive a
CBOM so reviewers can see what the scan saw.

```bash
# Fail the build on any high-or-above finding; persist the CBOM for upload
cradar scan ./service --fail-on high -o cbom.json --validate
```

GitHub Actions:

```yaml
- name: CipherRadar scan
  run: |
    cradar scan ./service \
      --fail-on high \
      -o cbom.json \
      -o issues.sarif \
      --validate

- name: Upload CBOM artifact
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: cbom
    path: cbom.json

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: issues.sarif
```

Exit codes are documented in [exit-codes.md](exit-codes.md).

---

## 2. Baseline + diff

Use a baseline to suppress pre-existing security findings on day one, then track newly
introduced findings going forward. Diff CBOMs across releases to see what changed in the
cryptographic surface.

```bash
# Day 0 — capture the current state as the baseline
cradar init
cradar scan ./service -o cbom-day0.json
cradar scan ./service --update-baseline   # writes .cradar-baseline.json

# Subsequent scans suppress baselined findings automatically
cradar scan ./service --fail-on high -o cbom.json

# When releasing, diff against the last shipped CBOM
cradar diff cbom-day0.json cbom.json
```

Stale baseline entries (suppressions for findings the scanner no longer detects) are reported
on stderr. Run with `--update-baseline` to refresh the file once the underlying code is fixed.

To take a one-off scan without the baseline:

```bash
cradar scan ./service --no-baseline
```

---

## 3. Container image scan

Scan a container image — registry reference or a local tar — for cryptographic assets inside
each layer.

```bash
# Scan a public image
cradar scan --container nginx:latest -o nginx.cbom.json

# Scan a private image (use the host docker / podman credentials)
cradar scan --container ghcr.io/acme/api:1.2.3 -o api.cbom.json

# Scan an exported image tarball — useful in air-gapped pipelines
docker save acme/api:1.2.3 -o api.tar
cradar scan --container ./api.tar -o api.cbom.json
```

The positional path argument and `--container` are mutually exclusive.

---

## 4. Push to the portal

Run a scan locally or in CI and upload the result to the CipherRadar portal. Project and group
default from `.cradar.yml` so the CI command stays short.

```yaml
# .cradar.yml
api_url: "https://cipherradar.company.com/api/v1"
api_key_env: "CRADAR_API_KEY"
project: "payment-service"
group: "platform/backend"
```

```bash
# CI pipeline
export CRADAR_API_KEY="${{ secrets.CRADAR_API_KEY }}"
cradar scan ./service --push --fail-on high -o cbom.json
```

CLI flags override the config file when both are present. The push happens after the local
scan succeeds, so a failed scan never produces a misleading uploaded result.

---

## 5. Inventory-only run

Skip the security taint analysis and emit a pure CBOM inventory — every algorithm, protocol,
certificate, and piece of key material the scanner found.

```bash
cradar scan ./service --only-inventory -o inventory.cbom.json
```

Inventory rules live in Pass 2. If OpenGrep is not installed, the run prints a hint and the
inventory will be empty. Run `cradar install-tools` first or use the `cradar-full` archive.

---

## 6. Pre-commit hook

Install a git hook that runs a fast scan on staged files before every commit. The hook fails
the commit on any `critical` finding, leaving lower-severity findings as warnings.

```bash
# Install in the current repo
cradar hook install

# Or install globally for every repo on this machine
cradar hook install --global
```

The hook itself runs:

```sh
cradar scan --fast --staged-only --fail-on critical
```

`--fast` skips files larger than 100 KB and runs only Pass 1, so the hook stays well under a
second on a typical commit.

Skip the hook for a single commit when needed:

```bash
git commit --no-verify
```

Uninstall:

```bash
cradar hook uninstall            # local
cradar hook uninstall --global   # global
```

The uninstaller refuses to remove a pre-commit hook it did not install — your custom hooks are
safe.

---

## 7. Generate a PDF executive report

Produce an executive-style PDF report for a governance review.

```bash
# Scan and write a PDF in one step
cradar scan ./service -o cbom.pdf

# Or render a PDF from an existing CBOM
cradar report cbom.json -o cbom-executive.pdf
```

`cradar report`'s default format is `pdf`, so you can also write:

```bash
cradar report cbom.json
# → report.pdf
```

---

## 8. SARIF upload to code scanning

Produce a SARIF file and upload it to GitHub Advanced Security so findings appear inline on
pull requests and in the Security tab.

```bash
cradar scan ./service -o cradar.sarif
```

GitHub Actions:

```yaml
- name: CipherRadar scan
  run: cradar scan ./service -o cradar.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cradar.sarif
    category: cradar
```

The same SARIF file is consumable by GitLab SAST, Azure DevOps, JetBrains IDEs, and VS Code
SARIF Viewer.

---

## 9. Air-gapped install

For runners with no internet access, ship the `cradar-full` archive. OpenGrep and YARA-X are
bundled inside the archive — `install-tools` is unnecessary.

```bash
# On a host with internet access
curl -L -o cradar-full.tar.gz \
  https://github.com/nk-sentinel/cipherradar/releases/download/<TAG>/cradar-full_linux_amd64.tar.gz

# Transfer to the air-gapped host, then
tar -xzf cradar-full.tar.gz
sudo mv cradar /usr/local/bin/cradar

# Verify
cradar version
cradar scan ./service -o cbom.json --validate
```

The lightweight `cradar` archive plus `cradar install-tools` still works in environments where
GitHub release downloads are reachable — `install-tools` verifies the SHA-256 of each binary
against the publisher's release digest before installing.

---

## 10. Multi-format export in one scan

`--output` is repeatable. Emit a CBOM, a SARIF report, a PDF, and a SonarQube issue file from a
single scan — no re-walks of the source tree, no duplicate work.

```bash
cradar scan ./service \
  -o cbom.json \
  -o issues.sarif \
  -o issues.sonar.json \
  -o report.pdf
```

Each path's format is dispatched from its extension. See [output-formats.md](output-formats.md)
for the full mapping.

---

## 11. Scanning compiled binaries for embedded crypto

Pass 3 (YARA-X) inspects compiled artifacts for cryptographic material that doesn't appear in
source: hard-coded private keys, pinned certificates, statically-linked OpenSSL banners, and
algorithm-specific byte tables like the AES S-box. Useful for:

- Firmware images / IoT builds where the source has long since drifted from what shipped
- Third-party JAR / wheel / native libraries vendored into your repo
- Verifying that a release artifact doesn't carry test keys or debug certs you forgot to strip

Pass 3 is opt-in. Default scans don't pay the cost.

### Scan a build output directory

```bash
# Lightweight binary — make sure yr is on PATH
cradar install-tools         # one-time; OpenGrep + YARA-X
cradar scan ./build/artifacts --passes 3 --format text

# cradar-full ships yr pre-bundled
cradar scan ./build/artifacts --passes 3 -o cbom.json --validate
```

Example output on a directory of ELF / JAR fixtures:

```
  Pass 3 (YARA-X):   +12 findings  [0.1s]

  CRITICAL    1     embedded_pem_rsa_private      service.so:0x4020
  HIGH        1     embedded_pem_certificate      service.so:0x3f80
  INFO       10     openssl_version_3_0, ...
```

### Combine with the standard passes

```bash
# Full pipeline: AST inventory + OpenGrep taint + YARA-X binary
cradar scan ./repo --deep -o cbom.json
# equivalent to --passes 1,2,3

# Just Pass 3 on a single artifact
cradar scan ./build/service.jar --passes 3
```

### Override the embedded ruleset

The 15-rule starter set is embedded in the binary. Point at your own rules directory to extend
or replace it:

```bash
# Extend: ship cradar's rules + add your in-house signatures
mkdir -p /etc/cradar/yara-rules
cp /path/to/cradar/extracted/*.yar /etc/cradar/yara-rules/
cp ./my-org-rules.yar              /etc/cradar/yara-rules/

CRADAR_YARA_RULES_DIR=/etc/cradar/yara-rules \
  cradar scan ./build --passes 3
```

Rule authoring conventions live in [`scanner/yara-rules/README.md`](../../../scanner/yara-rules/README.md)
in the repo — every rule needs `meta.cbom_primitive` to surface in the CBOM with a canonical
algorithm token.

### CI recipe: nightly binary-deep scan

Run binary scans nightly rather than on every PR (they're slower and the artifacts don't change
on every commit):

```yaml
# .github/workflows/cradar-binary-nightly.yml
name: cradar binary scan
on:
  schedule: [{cron: '0 3 * * *'}]
jobs:
  binary-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: |
          curl -L https://github.com/nk-sentinel/cipherradar/releases/latest/download/cradar-full_linux_amd64.tar.gz | tar -xz
          ./cradar scan ./dist --passes 3 -o cbom.json --validate
      - uses: actions/upload-artifact@v4
        with:
          name: nightly-binary-cbom
          path: cbom.json
```

### Limitations

- **Packed binaries** (UPX, etc.) hide all rule patterns — Pass 3 can't unpack.
- **Compressed PEM blobs** embedded inside ZIP / TAR layers inside binaries aren't reached
  unless the outer container is the scan target (use `--container` for OCI images).
- **AES-NI / hardware-accelerated paths** have a different byte signature than the table-based
  AES the current ruleset matches — coverage gap noted in `scanner/yara-rules/README.md`.
