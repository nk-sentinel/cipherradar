# Configuration Files

`cradar` reads two user-editable YAML files. Both are scaffolded by `cradar init` with
commented defaults.

| File                  | Purpose                                                          |
|-----------------------|------------------------------------------------------------------|
| `.cradar.yml`         | CLI defaults — output format, passes, push targets, rule filters |
| `policy.cradar.yml`   | Policy rules evaluated by `cradar policy check`                  |

The path to `.cradar.yml` can be overridden with the global `--config` flag; `policy.cradar.yml`
is selected per-invocation via `cradar policy check --policy`.

---

## .cradar.yml

Every key is optional. Missing keys fall back to the built-in default. Command-line flags always
override values set here.

### Fields

| Key | Type | Description |
|---|---|---|
| `api_url` | string | Portal API base URL used by `cradar scan --push`. |
| `api_key_env` | string | Name of the environment variable holding the portal API key. Resolved when `--api-key` and `CRADAR_API_KEY` are both unset. |
| `project` | string | Default project name for `--push` uploads. |
| `group` | string | Default group path for `--push` uploads. |
| `default_format` | string | Default output format when `--format` is unset and the destination extension does not dispatch. Values: `cyclonedx-json`, `sarif`, `text`, `table`, `pdf`, `sonarqube-generic`. |
| `passes` | list of int | Default scan passes. Currently `[1]` or `[1, 2]`. |
| `rule_filters` | object | Defaults for the rule-lifecycle / category filter flags. See below. |
| `custom_wrappers` | list of object | User-defined wrapper functions to detect as crypto calls. See below. |

### `rule_filters` block

| Key | Type | Description |
|---|---|---|
| `categories` | list of string | Limit findings to the listed categories. Values: `inventory`, `security`. |
| `rules` | list of string | Allowlist of rule IDs; overrides the default set. |
| `disabled_rules` | list of string | Rule IDs to exclude regardless of other settings. |
| `include_rules` | list of string | Per-rule opt-in; bypasses maturity and noise gates. |
| `include_experimental` | bool | Include rules marked `maturity: experimental`. |
| `include_noisy` | bool | Include rules marked `noise_risk: high`. |
| `include_deprecated` | bool | Silence the deprecation warning for `maturity: deprecated` rules. |

Each of these mirrors a CLI flag. The CLI flag wins when both are set.

### `custom_wrappers` block

Use this to teach `cradar` about an in-house crypto wrapper library. Each entry maps a function
call to a CBOM asset type and tells the scanner which positional arguments carry the
algorithm, key, and other parameters.

| Key | Type | Description |
|---|---|---|
| `name` | string | Fully qualified function name, e.g. `mycompany.crypto.encrypt`. |
| `language` | string | Source language. Examples: `python`, `java`, `go`, `javascript`. |
| `type` | string | CBOM asset type. Examples: `algorithm`, `protocol`. |
| `severity` | string | Finding severity. Values: `info`, `low`, `medium`, `high`, `critical`. |
| `parameters` | map<string,int> | Maps parameter roles to positional argument indices. Common keys: `key`, `algorithm`, `mode`, `iv`. |

### Full annotated example

```yaml
# .cradar.yml — CipherRadar CLI configuration

# Portal integration (cradar scan --push)
api_url: "https://cipherradar.company.com/api/v1"
api_key_env: "CRADAR_API_KEY"      # read the key from this env var
project: "payment-service"
group: "platform/backend"

# Default output format. Omit to use TTY-aware defaults.
default_format: cyclonedx-json

# Scan passes. 1 = AST inventory, 2 = OpenGrep taint.
passes: [1, 2]

# Rule-lifecycle filters. CLI flags always override these values.
rule_filters:
  categories: [inventory, security]
  include_experimental: false
  include_noisy: false
  disabled_rules:
    - cbom-python-weak-hash-legacy
  include_rules:
    - cbom-java-experimental-pqc-detect

# Custom wrapper functions mapped to CBOM asset types.
custom_wrappers:
  - name: "mycompany.crypto.encrypt"
    language: "python"
    type: "algorithm"
    severity: "info"
    parameters:
      key: 0
      data: 1
      algorithm: 2
```

---

## policy.cradar.yml

Policy files are evaluated by `cradar policy check` against a CBOM. Each rule has an ID, a
description, a severity, an action (`fail` or `warn`), and a `condition` block.

`cradar policy check`'s `--fail-on` flag reclassifies violations at or above the threshold to
FAIL and the remainder to WARN at report time, so a single policy file can be used in both
strict and advisory pipelines.

### Top-level shape

```yaml
rules:
  - id: <stable-rule-id>
    description: <human-readable summary>
    severity: <info | low | medium | high | critical>
    action: <fail | warn>
    condition:
      ...
```

### Condition primitives

| Key | Type | Matches when... |
|---|---|---|
| `deny_algorithms` | list of string | A finding uses any listed algorithm name. Examples: `md5`, `sha1`, `des`, `3des`, `rc4`. |
| `deny_modes` | list of string | A finding uses any listed cipher mode. Example: `ecb`. |
| `min_key_size` | int | A finding's key size is below this value. Pair with `algorithm`. |
| `algorithm` | string | Scopes `min_key_size` to a specific algorithm (e.g. `rsa`). |
| `deny_tls_versions` | list of string | A protocol finding uses any listed TLS version. Examples: `"1.0"`, `"1.1"`. |
| `deny_quantum_status` | list of string | A finding's quantum status matches. Values: `quantum-vulnerable`, `quantum-safe`, `broken`. |
| `min_severity` | string | A finding's severity is at or above this value. |

Multiple primitives in one condition are combined with logical AND.

### Full annotated example

```yaml
# policy.cradar.yml — CipherRadar policy rules

rules:
  - id: no-broken-algorithms
    description: "Deny broken cryptographic algorithms"
    severity: critical
    action: fail
    condition:
      deny_algorithms: ["md5", "sha1", "des", "3des", "rc4"]

  - id: no-ecb-mode
    description: "Deny ECB mode — no semantic security"
    severity: high
    action: fail
    condition:
      deny_modes: ["ecb"]

  - id: rsa-min-key-size
    description: "RSA keys must be at least 2048 bits"
    severity: high
    action: fail
    condition:
      algorithm: "rsa"
      min_key_size: 2048

  - id: no-legacy-tls
    description: "Deny TLS 1.0 and 1.1"
    severity: high
    action: fail
    condition:
      deny_tls_versions: ["1.0", "1.1"]

  - id: quantum-vulnerable-warning
    description: "Warn on quantum-vulnerable algorithms"
    severity: medium
    action: warn
    condition:
      deny_quantum_status: ["quantum-vulnerable"]
```

Pair the policy with a CI gate:

```bash
cradar policy check cbom.json --policy policy.cradar.yml --fail-on high
```

Anything at or above `high` exits 1 and fails the build. Lower-severity violations exit 2 and
can be surfaced as a warning step.

## Default ignores and `.cradarignore`

`cradar scan` skips non-source paths by default so it never re-ingests its own
output or vendored/build noise (gh #46). Precedence (lowest to highest):

1. **Built-in defaults** — VCS (`.git/`), dependencies/vendor (`node_modules/`,
   `vendor/`, `.venv/`, `venv/`, `site-packages/`, `bower_components/`, `Pods/`),
   build output (`target/`, `build/`, `dist/`, `out/`, `bin/`, `obj/`,
   `__pycache__/`), other tools' workdirs (`.scannerwork/`, `.gradle/`,
   `.terraform/`, `.pytest_cache/`, `.idea/`, `.vscode/`), cradar's own output
   (`.cradar-baseline.json`, CycloneDX/SARIF JSON, PDF), and minified/generated
   assets (`*.min.js`, `*.bundle.js`, `*.map`). Disable with `--no-default-ignores`.
2. **`.gitignore`** — honored by default so already-ignored build/vendor dirs are
   skipped for free. Disable with `--no-gitignore`.
3. **`.cradarignore`** — a project-root ignore file using gitignore syntax for
   scan-specific exclusions. Always honored when present.

Config files (`nginx.conf`, `openssl.cnf`, `java.security`, Dockerfile, k8s YAML),
certificate/key material (`certs/`, `*.pem`, `*.key`), and binaries are **not**
default-ignored so they remain scannable.
