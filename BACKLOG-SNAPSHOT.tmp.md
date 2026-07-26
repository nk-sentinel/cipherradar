<!-- ⚠️ TEMPORARY / SCRATCH FILE — DELETE IN A FUTURE COMMIT.
     Point-in-time backlog snapshot generated for pasting into a design/presentation
     tool that has no GitHub access. Not a source of truth — the GitHub issues are.
     Generated as of v0.4.0-rc.4. Do not keep this in the repo long-term. -->

# CipherRadar — Open Backlog (CLI + Runtime Agent)

*As of v0.4.0-rc.4. All major multi-phase plans are complete; this is the remaining discrete backlog. Each item is tagged **type** (bug / enhancement) and **severity** (high / medium / low), plus **deferred** where intentionally parked.*

## CLI — Bugs

**#83 · Container scans silently run Pass 1 only — `severity: HIGH`**
Scanning a container image with `--deep` or `--passes 2,3` silently runs only Pass 1 (tree-sitter). The Pass-2 (OpenGrep taint) and Pass-3 (YARA-X binary) flags are ignored for images with **no runtime warning**, so users get a false sense of a "deep" scan of the container. *Highest-priority open item — minimum fix is a runtime warning; full fix is real multi-pass on image layers.*

**#70 · CBOM coverage/quality gaps — `severity: MEDIUM`**
Two defects: (a) Dart/Go library **purl** resolution only fires when a Pass-2 rule matches, so some libraries miss their package identity; (b) base64 certificates embedded in Kubernetes Secrets are **double-counted**.

**#82 · Pass-3 temp-dir leak — `severity: LOW`**
Pass 3 (YARA-X) leaves behind `/tmp/cradar-yara-rules-*` temp directories that are never cleaned up.

## CLI — Enhancements

**#45 · Data-flow misuse detection — `severity: MEDIUM`**
Detect cryptographic **misuse** patterns via data-flow analysis: fixed-seed `SecureRandom`, static/reused IVs. Goes beyond "is this API present" to "is it used unsafely."

**#49 · `--asset-type` / `--exclude-type` output filters — `severity: LOW`**
Let users scope CBOM output to (or exclude) specific asset types — algorithm / certificate / protocol / related-crypto-material.

**#74 · gosec SAST gate → blocking — `severity: LOW`**
Triage the gosec (SAST) baseline, then flip the CI gosec gate from advisory to blocking.

**#94 · BouncyCastle keystore helper *(deferred)* — `severity: LOW`**
Optional Java/BouncyCastle-backed helper to enumerate certificates inside the **encrypted** keystore formats (BCFKS/UBER). Deferred — those stores are already captured presence-only; enumeration needs the store password + a bundled BC jar.

**#95 · Pure-Go BCFKS reader *(deferred)* — `severity: LOW`**
A pure-Go BCFKS reader for no-JRE / air-gapped environments (read BCFKS certs without Java). Deferred / demand-driven.

## Runtime Agent *(new area — future)*

**#110 · Runtime crypto collection agent (eBPF) *(deferred)* — `severity: LOW`**
A dedicated agent rolled out to hosts/containers that observes cryptography **at runtime** (eBPF TLS interception — negotiated cipher suites, TLS versions, certs) **without requiring app instrumentation**. This is the rejected "Option B" from ADR-028; the OTel Collector exporter plugin was shipped instead (no agent, no privileged access). Deferred/exploratory — parked as a future advanced option (privileged/root, Linux-only, operationally heavy).

---

## Summary

| Area | Open | Bugs | Enhancements | Deferred |
|---|---|---|---|---|
| **CLI** | 8 | 3 (#83 high, #70 med, #82 low) | 5 | 2 (#94, #95) |
| **Runtime Agent** | 1 | – | 1 | 1 (#110) |

**Nothing critical.** The one item worth prioritizing is **#83** (container deep-scan silently no-ops). Everything else is medium/low; the deferred items (#94/#95/#110) are intentionally parked.

*(Out of CLI scope, not shown above: #87 backend `_extract_key_size` bug, #69 CI release-workflow tweak.)*
</content>
