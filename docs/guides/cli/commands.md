# Command Reference

Every `cradar` subcommand, every flag. Defaults are shown as they appear in the binary.

## Global flags

These persistent flags are available on every subcommand:

| Flag | Default | Description |
|---|---|---|
| `--config string` | `.cradar.yml` | Path to the configuration file. |
| `--verbose` | `false` | Enable verbose log records. |
| `--debug` | `false` | Enable debug-level logs. |
| `--quiet` | `false` | Suppress info output; only log errors. |
| `--log-file string` | (auto) | Override the log file path. Default: `~/.cradar/logs/cradar-<ts>-<pid>.log.jsonl`. |
| `--log-format string` | `json` | Log file format. One of `json`, `text`. |
| `--log-include-source` | `false` | Include matched source snippets in logs. Off by default for privacy. |

Logs are pruned to the most recent 10 files on startup. On any non-zero exit, `cradar` prints
`cradar: see log at <path>` to stderr so the log is easy to attach to a bug report.

---

## cradar scan

Scan a project directory or container image for cryptographic assets.

When `--container` is set, the argument is an image reference (for example `nginx:latest`,
`gcr.io/project/image:tag`) or a local tar file path. `--container` and a positional path are
mutually exclusive.

### Synopsis

```
cradar scan [path] [flags]
cradar scan --container <image-ref> [flags]
```

### Output flags

| Flag | Default | Description |
|---|---|---|
| `-o`, `--output strings` | `(stdout)` | Output file path. Repeat to write multiple artifacts in one scan; format is inferred from each extension. See [output formats](output-formats.md). |
| `-f`, `--format string` | `(auto)` | Override the format when writing to stdout, or for a single `--output`. Valid: `cyclonedx-json`, `sarif`, `text`, `table`, `pdf`, `sonarqube-generic`. |
| `--validate` | `false` | Validate output against the embedded CycloneDX 1.7 schema. Only meaningful when at least one sink produces `cyclonedx-json`. |
| `--strict-validate` | `false` | Fail the scan if any output value falls outside the CycloneDX 1.7 closed enum sets. Default behavior is warn-only. |

### Pass / engine flags

| Flag | Default | Description |
|---|---|---|
| `--passes string` | `1,2` | Comma-separated list of passes to run. `1` = AST inventory; `2` = OpenGrep taint; `3` = YARA-X binary content. |
| `--deep` | `false` | Alias for `--passes 1,2,3` (full pipeline including binary scanning). |
| `--fast` | `false` | Pass 1 only; skip files larger than 100 KB. Designed for the pre-commit hook. |
| `--rules-dir string` | `(embedded)` | External directory of OpenGrep YAML rules to use instead of the embedded set. Also reads `CRADAR_RULES_DIR`. |
| `--severity string` | `low` | Minimum severity level to report. |
| `--branch string` | | Git branch to scan (for git URL inputs). |

When `--deep` or `--passes` is given explicitly and the required tool (OpenGrep for pass 2,
YARA-X for pass 3) is missing, `cradar` exits 4 (`ExitToolMissing`). When a pass runs only as
part of the default set, the missing tool degrades to a warning and the pass is skipped.

#### Pass 3 — binary content scanning (YARA-X)

Pass 3 runs the bundled YARA-X engine (`yr`) over compiled artifacts to detect cryptographic
material that isn't visible in source: embedded certificates, hard-coded private keys, library
fingerprints (OpenSSL / libsodium / BoringSSL / mbedTLS), and algorithm-defining byte tables
(AES S-box, MD5/SHA initial state). The starter ruleset ships embedded with the CLI; override
with `CRADAR_YARA_RULES_DIR` if you need to extend or replace the default set.

Pass 3 is **opt-in** — it's not in the default `--passes 1,2` set so binary-heavy repos don't
pay the cost on every scan. Enable it via `--passes 3` (Pass 3 only), `--passes 1,2,3` (full
pipeline), or `--deep` (alias for 1,2,3).

File types Pass 3 examines: `.so`, `.dll`, `.dylib`, `.exe`, `.a`, `.o`, `.class`, `.jar`,
`.whl`, `.wasm`, plus extensionless executables. Source files are skipped — language scanners
(pass 1) handle those. Pass 3 runs **alongside** the native binary scanner on the same files
when both are enabled; the two engines produce complementary findings (de-duplicated by
`Finding.Fingerprint`).

### Rule / category filters

| Flag | Default | Description |
|---|---|---|
| `--category strings` | | Limit findings to categories. Repeatable. Values: `inventory`, `security`. |
| `--only-inventory` | `false` | Shortcut for `--category inventory`. |
| `--only-security` | `false` | Shortcut for `--category security`. |
| `--rules strings` | | Explicit allowlist of rule IDs; overrides the default set. |
| `--disable-rule strings` | | Rule IDs to exclude. Repeatable. Trumps every other include flag. |
| `--include-rule strings` | | Per-rule opt-in; bypasses maturity and noise gates. |
| `--include-experimental` | `false` | Include rules marked `maturity: experimental`. |
| `--include-noisy` | `false` | Include rules marked `noise_risk: high`. |
| `--include-deprecated` | `false` | Silence the deprecation warning for `maturity: deprecated` rules. |

`--only-inventory` without pass 2 deterministically returns zero findings (inventory rules live
in Pass 2). `cradar` prints a hint on stderr in that case rather than failing silently.

**Inventory vs security, and what each filter keeps.** A default scan (no category flag)
emits **everything** — the full inventory plus all security findings; nothing is hidden.
`--only-inventory` keeps inventory-tagged findings **plus any finding that carries a concrete
crypto-asset identity**, so weak/broken algorithms (MD5, DES, RC4) — which are tagged
`security` — still appear because they *are* crypto assets; it is a complete asset list.
`--only-security` is the only filter that drops pure-inventory findings (an algorithm in use
with no associated risk). Baseline suppression likewise only ever removes security findings,
never inventory.

### Scanning / ignore controls

| Flag | Default | Description |
|---|---|---|
| `--no-default-ignores` | `false` | Disable the built-in default ignores (VCS, vendor/dependency dirs, build output, other tools' workdirs, cradar's own output, and minified/generated assets). See [configuration](configuration.md#default-ignores-and-cradarignore). |
| `--no-gitignore` | `false` | Do not honor `.gitignore` during the scan. |

By default `cradar` skips non-source paths so it never re-ingests its own output or
vendored/build noise. A project-root `.cradarignore` (gitignore syntax) adds scan-specific
exclusions. Config files, certificate/key material, and binaries are never default-ignored.

### Keystore inspection

| Flag | Default | Description |
|---|---|---|
| `--keystore-wordlist string` | | Path to a newline-delimited password list to try (in addition to the built-in defaults) when opening JKS / PKCS#12 keystores. Never downloads wordlists. |

`cradar` inspects keystore files (`.jks`, `.keystore`, `.p12`, `.pfx`, `.truststore`),
enumerating the certificates inside and flagging any store that opens with a well-known or
default password. `.bks` (BouncyCastle) keystores are reported presence-only — see
[ADR-041](../../decisions/ADR-041-keystore-password-policy.md).

### Hook / staged-only

| Flag | Default | Description |
|---|---|---|
| `--staged-only` | `false` | Only scan files staged in git (`git diff --cached --name-only`). |
| `--fail-on string` | | Exit non-zero if findings at or above this severity. Values: `critical`, `high`, `medium`, `low`, `info`. |

### Container

| Flag | Default | Description |
|---|---|---|
| `--container string` | | Scan a container image. Accepts a registry reference or a local `.tar` path. Mutually exclusive with the positional path. |

### Baseline suppression

| Flag | Default | Description |
|---|---|---|
| `--baseline-file string` | `.cradar-baseline.json` | Path to the baseline file used for suppression. |
| `--no-baseline` | `false` | Ignore the baseline file for this run. |
| `--update-baseline` | `false` | Rewrite the baseline file from this run's security findings. |
| `--baseline string` | | Path to a *previous scan's* CycloneDX JSON. Adds a "Changes vs Baseline" section to PDF reports. Distinct from `--baseline-file` (suppression). |

Baseline applies after rule filters and fingerprinting, so every output writer and the `--fail-on`
gate see the same suppressed set. Stale entries are reported on stderr.

### Push to portal

| Flag | Default | Description |
|---|---|---|
| `--push` | `false` | Upload scan results to the CipherRadar portal after the scan succeeds. |
| `--project string` | | Project name on the portal. Required with `--push`. Falls back to `project` in `.cradar.yml`. |
| `--group string` | | Group path on the portal. Falls back to `group` in `.cradar.yml`. |
| `--api-url string` | | Portal API URL. Falls back to `api_url` in `.cradar.yml`. |
| `--api-key string` | | API key. Also reads `CRADAR_API_KEY` and `api_key_env` in `.cradar.yml`. |

### Examples

```bash
# Default scan, terminal-friendly summary on TTY; CBOM JSON when redirected
cradar scan ./service

# Multi-format export in one run (extension dispatch picks the writer)
cradar scan ./service -o cbom.json -o report.pdf -o issues.sarif

# Validate against the embedded CycloneDX 1.7 schema
cradar scan ./service -o cbom.json --validate

# Inventory only — algorithms, certs, key material, no taint analysis
cradar scan ./service --only-inventory -o inventory.json

# CI gate — fail on any high-or-above finding
cradar scan ./service --fail-on high -o cbom.json

# Pre-commit hook style — staged files, pass 1 only, critical gate
cradar scan . --fast --staged-only --fail-on critical

# Scan a container image
cradar scan --container nginx:latest -o nginx.cbom.json

# Push results to the portal
cradar scan ./service --push --project payments --api-key "$CRADAR_API_KEY"
```

---

## cradar diff

Compare two CBOM files and show what changed — added, removed, or modified cryptographic assets.

### Synopsis

```
cradar diff <before.json> <after.json> [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-o`, `--output string` | `(stdout)` | Output file path. |
| `-f`, `--format string` | `text` | Output format. One of `text`, `json`. |

### Examples

```bash
# Side-by-side text diff
cradar diff cbom-before.json cbom-after.json

# Machine-readable JSON diff for a release tool
cradar diff cbom-before.json cbom-after.json -f json -o diff.json
```

---

## cradar policy

Policy management commands. The only subcommand today is `check`.

### cradar policy check

Evaluate a CBOM against a policy file. The policy file lists rules — denied algorithms, key
size minimums, TLS version floors, quantum-status filters — and assigns each rule a severity.

#### Synopsis

```
cradar policy check <cbom.json> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `-p`, `--policy string` | `policy.cradar.yml` | Path to the policy file. |
| `--fail-on string` | `critical` | Minimum severity that causes a non-zero exit. Values: `critical`, `high`, `medium`, `low`, `info`. |

#### Exit codes

`policy check` uses the standard table (see [exit-codes.md](exit-codes.md)):

- `0` — every rule passed.
- `1` — at least one violation at or above `--fail-on`.
- `2` — violations exist but all are below `--fail-on` (warn-only).

#### Examples

```bash
# Fail CI on any critical-or-above policy violation (default)
cradar policy check cbom.json --policy policy.cradar.yml

# Stricter gate — any high-or-above breaks the build
cradar policy check cbom.json --policy policy.cradar.yml --fail-on high
```

---

## cradar report

Generate a human-readable report from an existing CBOM file. Useful when a CBOM was produced
upstream (for example by `cradar scan --push`) and a downstream consumer needs a PDF or table.

### Synopsis

```
cradar report <cbom.json> [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-o`, `--output string` | `report.<ext>` | Output file path. Format is inferred from the extension when set. |
| `-f`, `--format string` | `pdf` | Output format override. Same set as `scan --format`. When `--output` has no recognised extension the format falls back to `pdf`. |

### Examples

```bash
# Generate the default PDF executive report
cradar report cbom.json -o cbom-report.pdf

# Render a table view of findings to stdout
cradar report cbom.json -f table
```

---

## cradar rules

Inspect the embedded rule corpus.

### cradar rules list

List every embedded rule with its lifecycle metadata.

#### Synopsis

```
cradar rules list [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--format string` | `table` | Output format. One of `table`, `json`. |
| `--category string` | | Filter by category. One of `inventory`, `security`. |
| `--maturity string` | | Filter by maturity. One of `experimental`, `stable`, `deprecated`. |
| `--only-default-off` | `false` | Show only rules that are off by default. |

### cradar rules explain

Show metadata and guidance for one rule.

#### Synopsis

```
cradar rules explain <rule-id>
```

### Examples

```bash
# Browse the security rules
cradar rules list --category security

# Show only opt-in rules
cradar rules list --only-default-off

# JSON view for tooling
cradar rules list --format json

# Drill into a single rule
cradar rules explain cbom-python-weak-hash
```

---

## cradar init

Scaffold `.cradar.yml` and `policy.cradar.yml` in the current directory (or `--dir`). Refuses
to overwrite existing files unless `--force` is given.

### Synopsis

```
cradar init [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--force` | `false` | Overwrite existing `.cradar.yml` / `policy.cradar.yml`. |
| `--dir string` | `.` | Directory to scaffold into. |

### Examples

```bash
# First-time setup
cradar init

# Reset to the shipped templates
cradar init --force
```

---

## cradar hook

Manage the git pre-commit hook. The installed hook runs:

```sh
cradar scan --fast --staged-only --fail-on critical
```

### cradar hook install

#### Synopsis

```
cradar hook install [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--global` | `false` | Install as the git global hook (`~/.config/git/hooks`). Sets `core.hooksPath` globally. |

The installer refuses to overwrite a pre-commit hook it did not create. Hooks installed by
`cradar` carry a `# CipherRadar pre-commit hook` marker so uninstall is safe.

### cradar hook uninstall

#### Synopsis

```
cradar hook uninstall [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--global` | `false` | Uninstall the git global hook. |

### Examples

```bash
# Install in the current repository
cradar hook install

# Install globally for every repo on this machine
cradar hook install --global

# Skip the hook for a single commit
git commit --no-verify
```

---

## cradar completion

Generate a shell completion script.

### Synopsis

```
cradar completion {bash | zsh | fish | powershell}
```

### Examples

```bash
# Bash — current shell
source <(cradar completion bash)

# Bash — persistent (Linux)
cradar completion bash | sudo tee /etc/bash_completion.d/cradar > /dev/null

# Zsh — persistent
cradar completion zsh > "${fpath[1]}/_cradar"

# Fish
cradar completion fish | source

# PowerShell
cradar completion powershell | Out-String | Invoke-Expression
```

---

## cradar install-tools

Download and install the external analysis tools cradar needs for Pass 2 and binary scanning.
Tools are installed to `~/.cradar/tools/` by default. Each binary is downloaded over HTTPS and
verified against the publisher's SHA-256 digest before being made executable.

Installs:

- OpenGrep — taint analysis engine for Pass 2
- YARA-X — binary scanning engine for compiled artifacts

### Synopsis

```
cradar install-tools [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--tools-dir string` | `~/.cradar/tools` | Directory to install tools into. |
| `--force` | `false` | Reinstall tools even if already present. |

### Examples

```bash
# First-time install
cradar install-tools

# Reinstall after a corrupted download
cradar install-tools --force

# Install to a shared location for a CI runner
cradar install-tools --tools-dir /opt/cradar/tools
```

The `cradar-full` distribution ships with both tools already bundled and does not need this
command.

---

## cradar admin

Administrative commands. Intended for break-glass recovery; not used during normal scans.

### cradar admin reset-password

Reset an admin user's password by emitting the bcrypt-hashed SQL to apply against the portal
database. Designed for the case where every Org Admin is locked out of the web UI.

#### Synopsis

```
cradar admin reset-password --email <email> [flags]
```

#### Flags

| Flag | Default | Description |
|---|---|---|
| `--email string` | | (required) Email address of the user to reset. |
| `--database-url string` | (env) | PostgreSQL connection string. Falls back to `CRADAR_DATABASE_URL`. |

#### Examples

```bash
# Generate the SQL to run against the portal database
cradar admin reset-password --email alice@example.com
```

The command prints a temporary password and the corresponding `UPDATE users` SQL statement. The
administrator runs the SQL manually against the database; `cradar` itself does not connect.

---

## cradar version

Print the binary version, commit SHA, build date, and the embedded CycloneDX schema version.

### Synopsis

```
cradar version
```

---

## cradar help

Standard cobra help. Use it for the top-level help screen or the help for any subcommand:

```bash
cradar help
cradar help scan
cradar scan --help
```
