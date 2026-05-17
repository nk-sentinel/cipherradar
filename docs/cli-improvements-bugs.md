# CLI Improvements RC1 — Bug Inventory

Issues observed against `feature/cli-improvements` @ `a362d8f`
(VERSION `0.2.0-rc.1`) while exercising the CLI end-to-end against
`/home/nk-sentinel/projects/CipherRadarTestProj` on 2026-05-09.

Test bench: `cradar` built fresh from `cli/cmd/cradar`; OpenGrep
v1.16.5 installed manually at `~/.cradar/tools/opengrep` (see Bug 5
for why `install-tools` could not produce it).

Severity legend:

- **Critical** — silently changes scan results; user has no way to
  notice from the CLI alone.
- **High** — wrong exit code; CI assumes success when the run was
  invalid.
- **Medium** — surprising behaviour, but observable.
- **Low** — cosmetic / docs.

---

## 1. Silent success on a missing scan path  *(High)*

```bash
$ cradar scan /no/such/path --passes 1
# stdout: a perfectly-formed empty CycloneDX 1.7 document
# stderr: (none)
$ echo $?
0
```

Expected: exit 3 (config/IO error per ADR-036) plus a clear "path
does not exist" message.

Impact: a typo'd path in CI passes green and uploads an empty CBOM.

Likely fix site: target validation in `cli/internal/cmd/scan.go`
between flag parsing and `scanner.ScanDirWithOptions`.

---

## 2. `--category` typo returns exit 1 instead of exit 3  *(Medium)*

```bash
$ cradar scan auth --category bogus
Error: invalid --category value "bogus" (valid: inventory, security)
$ echo $?
1
```

ADR-036 reserves exit 1 for "findings at/above `--fail-on`" and exit 3
for "config/schema error". This validator is at
`cli/internal/cmd/scan.go:723` and returns a plain `fmt.Errorf`; the
call site doesn't wrap it as `ExitError(ExitConfigError)`.

Fix: in `parseRuleFilterOptions`, return
`ExitErrorf(ExitConfigError, "...")` instead of `fmt.Errorf`.

---

## 3. `--debug` and `--log-include-source` produce no extra output  *(Low)*

`--debug` only emits two log lines per run (`scan started` /
`scan complete`). No per-scanner, per-finding, or per-rule debug
events fire. `--log-include-source` adds no `source` field anywhere
in the JSONL.

This is consistent with the "concurrent-scan log interleaving"
follow-up that was deferred from item 2; flagging here so it's not
forgotten. Either wire the instrumentation or remove the flags until
they do something.

---

## 4. `--only-inventory` returns 0 in pass-1-only scans  *(Low — by design, but counter-intuitive)*

Findings produced by the AST tree-sitter scanner have no rule-derived
category metadata, so `cli/internal/rulefilter/filter.go:247`
normalises empty `Category` to `security`. With opengrep absent
(or broken — see Bug 6), every finding is `security`, so
`--only-inventory` deterministically returns 0.

Fix options:

- Detect `OnlyInventory` requested but `pass2_findings == 0` and emit
  a one-line hint: `"--only-inventory matched 0 findings; inventory
  rules require Pass 2 (run 'cradar install-tools')"`.
- Or document that inventory categorisation is rule-driven and Pass 2
  must run.

---

## 5. `cradar install-tools` 404s on linux/amd64  *(High)*

```text
Downloading OpenGrep v1.16.5 for linux/x86_64...
URL: https://github.com/opengrep/opengrep/releases/download/v1.16.5/opengrep-core_linux_x86_64.tar.gz
Error: HTTP 404
```

Fix site: `cli/internal/tools/installer.go:57-58`

```go
if arch == "amd64" {
    arch = "x86_64"   // ← wrong; OpenGrep ships as "x86"
}
```

Across every published OpenGrep release (including the pinned v1.16.5)
the linux x86_64 asset is named `opengrep-core_linux_x86.tar.gz`, not
`..._linux_x86_64.tar.gz`. The tarball even contains a 32-bit-named
binary that is in fact 64-bit; the project just calls it "x86".

Two-line fix: drop the `amd64 → x86_64` rewrite (Go's `runtime.GOARCH`
gives `amd64`, but the file we want is `x86`), or simpler — switch to
the standalone single-file binary `opengrep_manylinux_x86` published
at the release root, which doesn't need extraction.

YARA-X install in the same command works fine.

---

## 6. **CRITICAL**: Pass 2 silently produces 0 findings  *(Critical)*

`cradar scan --passes 2` (or `--deep`) returns success and the same
findings as `--passes 1` whenever **any** rule file in the rules
directory contains a "broken rule" (see Bug 7 for what that means).

### What's actually happening

`cli/internal/opengrep/runner.go:91` invokes opengrep as:

```text
opengrep scan --config <rulesDir> --json --no-git-ignore <target>
```

The `<rulesDir>` is a *directory* containing per-language YAML files.
When OpenGrep encounters a single file with an `InvalidRuleSchemaError`
or a pattern-parse error, it bails out of the entire load with:

```json
{
  "results": [],
  "errors": [
    {"type": "InvalidRuleSchemaError", ...},
    {"type": "SemgrepError", "message": "invalid configuration file found (1 configs were invalid)"}
  ],
  "paths": {"scanned": []}
}
```

Critically: **`paths.scanned` is empty** — opengrep does not run
*any* rule against *any* file once one rule file is rejected. Other
valid rules in the same directory are dropped on the floor.

`cli/internal/opengrep/parser.go:63` deserialises this into the
`opengrepOutput` struct (which has an `Errors` field), then iterates
`output.Results` (length 0) and returns 0 findings with `nil` error.
The `Errors` slice is never inspected. `runPass2` reports success.

### Reproduction (verified 2026-05-09)

```bash
# Direct opengrep — what should be running
opengrep scan --config scanner/rules/javascript.yml \
              --no-git-ignore CipherRadarTestProj/javascript --json \
  | jq '.results | length'   # → 12

# Direct opengrep with the whole dir — what cradar actually invokes
opengrep scan --config scanner/rules/ \
              --no-git-ignore CipherRadarTestProj/javascript --json \
  | jq '.results | length'   # → 0  (because python.yml is broken)

# cradar pass 2 with a clean subset (csharp/js/php/ruby only)
cradar scan CipherRadarTestProj/javascript --passes 2 \
        --rules-dir /tmp/clean-rules \
        --include-experimental --include-noisy
# → 35 findings, 6 of them new from opengrep (4 inventory + 2 security)

# cradar pass 2 with the full broken rules set
cradar scan CipherRadarTestProj/javascript --passes 2 \
        --rules-dir scanner/rules
# → 29 findings, all from pass 1 AST (zero opengrep contribution)
```

### Fix paths (any one of these would unbreak Pass 2)

1. **Surface errors.** In `parser.ParseResults`, if
   `len(output.Errors) > 0 && len(output.Results) == 0`, return an
   error that names the offending rule files. Cradar can then either
   abort with exit 4 (tool failure) or warn and continue.
2. **Skip broken files at load time.** Iterate `*.yml` in `rulesDir`
   and pre-validate each file with a cheap `opengrep validate <file>`
   pass (or YAML schema check) before invoking the scan; pass only
   the files that load. This is the cleanest path because it doesn't
   block on rule fixes.
3. **Fix the rules** (see Bug 7). Necessary for full coverage but
   doesn't prevent regressions when rules drift against newer
   opengrep releases.

Best to combine 1+2: skip-and-warn so users see "Pass 2 dropped
python.yml: invalid metavariable-comparison schema" without losing
the rest of the scan.

---

## 7. Broken rules in the shipped rule corpus  *(Critical — paired with Bug 6)*

### What "broken rule" means in this context

Rules under `scanner/rules/*.yml` are OpenGrep/Semgrep-format
detectors. A rule is "broken" when **OpenGrep v1.16.5 refuses to
load it** — not when it produces wrong findings. Two distinct failure
modes:

#### Mode A: Schema rejection (`InvalidRuleSchemaError`)

The YAML is well-formed but uses a field shape OpenGrep's JSON Schema
doesn't accept.

**Example — `scanner/rules/python.yml:86`:**

```yaml
- pattern: |
    PBKDF2HMAC(
      ...,
      iterations=$N,
      ...
    )
  metavariable-comparison:
    metavariable: $N
    comparison: $N < 100000
```

OpenGrep 1.16.5 returns:

```text
'metavariable-comparison': {'metavariable': '$N', 'comparison': '$N < 100000'}
is not valid under any of the given schemas
```

The schema now requires `metavariable-comparison` to be either nested
inside a `patterns:` list element as its own `metavariable-comparison:`
sibling block, or expressed via `metavariable-pattern:`. The current
shape (a peer key under a single `pattern:` entry) is no longer
accepted.

**Example — `scanner/rules/go.yml:66`:**

```yaml
patterns:
  - pattern: rand.Read(...)
    fix: Use crypto/rand.Read() instead of math/rand.
  - pattern: rand.Int(...)
```

OpenGrep rejects `fix:` as a sibling of `pattern:` inside a `patterns:`
list — `fix` lives at the rule level, not the per-pattern level.

#### Mode B: Pattern parse error (`Invalid pattern for <Lang>`)

The pattern can't be tokenised by the language's grammar.

**Example — `scanner/rules/java.yml:154` (`cbom-java-crypto-library-import`):**

```yaml
pattern-either:
  - pattern: import org.bouncycastle.$...;
  - pattern: import javax.crypto.$...;
  - pattern: import java.security.$...;
  - pattern: import javax.net.ssl.$...;
```

OpenGrep's Java parser rejects `$...` here. Semgrep-style ellipsis
in import paths needs `$X...` (named) or just `...` (anonymous);
`$...` is not a recognised token in Java context.

**Example — `scanner/rules/dart.yml:2` (`cbom-dart-hardcoded-key`):**

```yaml
patterns:
  - pattern: |
      final $KEY = Key.fromUtf8("...");
```

OpenGrep's Dart parser returns `Failure: not implemented`. Several
Dart pattern shapes (variable-binding plus method-call chains) aren't
yet supported in 1.16.5's Dart frontend.

### Per-file status against OpenGrep 1.16.5

| File | Status | Errors | What's affected |
|---|---|---|---|
| `cpp.yml` | clean | 0 | — |
| `csharp.yml` | clean | 0 | — |
| `dart.yml` | **broken** | 2 parse errors | `cbom-dart-hardcoded-key`, `cbom-dart-insecure-random` reject the whole file |
| `go.yml` | **broken** | 2 schema errors | `fix:` field on `cbom-go-weak-rand` rejects the whole file |
| `java.yml` | partial | 1 parse error | `cbom-java-crypto-library-import` dropped; rest run |
| `javascript.yml` | clean | 0 | — |
| `kotlin.yml` | partial | 1 parse error | `cbom-kotlin-crypto-library-import` dropped; rest run |
| `php.yml` | clean | 0 | — |
| `python.yml` | **broken** | 2 schema errors | `metavariable-comparison` shape rejects the whole file |
| `ruby.yml` | clean | 0 | — |
| `rust.yml` | **broken** | 2 parse errors | `cbom-rust-weak-tls`, `cbom-rust-crypto-library-import` reject the whole file |
| `swift.yml` | clean | 0 | — |

"**broken**" means: OpenGrep returns `paths.scanned=[]` for that file
in isolation. Combined with Bug 6's whole-dir invocation, ANY broken
file kills the entire scan — Python and Go users get zero opengrep
coverage even when their language files are fine.

### Fix path

For schema rejections (python.yml, go.yml): rewrite the patterns to
the current schema. `metavariable-comparison` should look like:

```yaml
patterns:
  - pattern: hashlib.pbkdf2_hmac(..., ..., ..., iterations=$N)
  - metavariable-comparison:
      metavariable: $N
      comparison: $N < 100000
```

For parse errors (dart, rust, java, kotlin import patterns): switch
`$...` to `...` (anonymous ellipsis) for the import suffix. Imports
become:

```yaml
- pattern: import org.bouncycastle...;
- pattern: import javax.crypto...;
```

Each fix should be paired with a regression test that runs the rule
file through `opengrep validate` so future drift fails CI rather than
silently disabling pass 2.

---

## 8. OpenGrep rule-ID prefix not stripped in cradar output  *(Medium)*

When OpenGrep is invoked with a rules *directory*, it namespaces every
`check_id` by the directory path with dots:

```bash
$ opengrep scan --config /tmp/clean-rules --json ... | jq '.results[].check_id' | head -2
"tmp.clean-rules.cbom-js-crypto-library-import"
"tmp.clean-rules.cbom-js-hardcoded-jwt-secret"
```

`cli/internal/opengrep/parser.go:76` sets `RuleID = r.CheckID`
verbatim, so cradar's SARIF / CycloneDX output ends up with rule IDs
like `tmp.clean-rules.cbom-js-crypto-library-import`.

Consequences:

- `--rules cbom-js-crypto-library-import` allowlist filter never matches
  opengrep findings (would need the full prefixed ID).
- `--disable-rule cbom-js-...` similarly broken for opengrep findings.
- `cradar rules explain <id>` — the rule corpus uses bare IDs, so the
  IDs in scan output don't round-trip back to the rule definitions.

Fix in `parser.deriveNameFromCheckID` or before assigning `RuleID`:
strip everything up to and including the last `.` so
`tmp.clean-rules.cbom-js-crypto-library-import` becomes
`cbom-js-crypto-library-import`.

A rule ID like `cbom-foo.cbom-bar` is implausible (real rule IDs use
dashes), so a simple `strings.LastIndex(checkID, ".")` is safe.

---

## Summary of fix priorities

| # | Severity | Effort | Why it should land first |
|---|---|---|---|
| 6 | Critical | small (1) + medium (2) | Pass 2 is documented as a flagship feature and is silently a no-op for a large fraction of users |
| 7 | Critical | medium | Pairs with #6 — fixing #6 alone leaves Python/Go/Dart/Rust users with reduced coverage |
| 1 | High | small | CI-shaped trap: a broken pipeline appears green |
| 5 | High | trivial (1-line) | Blocks fresh-install onboarding |
| 8 | Medium | trivial (1-line) | Breaks `--rules`/`--disable-rule` integration with opengrep |
| 2 | Medium | trivial | Wrong exit code per documented contract |
| 4 | Low | trivial | UX hint |
| 3 | Low | medium | Wired flags with no instrumentation; either land or remove |

A reasonable single-PR scope: 6 + 7 + 5 + 8 (the OpenGrep-pipeline
group), then 1 + 2 + 4 as a follow-up CLI-polish PR.

---

## rc2 status (2026-05-18)

| # | Status | Fix commit |
|---|---|---|
| 1 | FIXED | 530f487 |
| 2 | FIXED | 5af9364 |
| 3 | FIXED | 7747905 |
| 4 | FIXED (hint added) | 3b80373 |
| 5 | FIXED (GitHub API digest verification) | 4111521 |
| 6 | FIXED (cradar hardening) | 2fafb02 |
| 7 | OUT OF SCOPE for rc2 (rule rewrites deferred) | — |
| 8 | FIXED | e4a1036 |
