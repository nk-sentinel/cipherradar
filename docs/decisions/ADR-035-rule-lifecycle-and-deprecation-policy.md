# ADR-035: Rule Lifecycle & Deprecation Policy

**Status:** Accepted
**Date:** 2026-04-15
**Decision Makers:** Development team
**Phase:** CLI improvements (item 1: category + filter + lifecycle + baseline)

## Context

The OpenGrep rule corpus has grown from a handful of hand-picked patterns
to ~80 rules across 12 languages. Three problems surfaced:

1. **Noisy rules block adoption.** Pattern-based detections for hardcoded
   keys / IVs routinely fire on test fixtures and tutorial code. A user
   running `cradar scan` for the first time sees hundreds of findings and
   abandons the tool before ever hitting the real issues.
2. **No safe way to iterate on rule signal.** Rule authors have no
   signal to mark a rule as "this works for me, not production-ready".
   Every rule lands on every repo the day it merges.
3. **No way to retire a bad rule.** When a pattern turns out to produce
   mostly false positives, the only options were "leave it in forever" or
   "delete it immediately and break everyone running `--fail-on`".

## Decision

Add three fields to every OpenGrep rule's `metadata` block:

```yaml
metadata:
  category: security | inventory
  maturity: experimental | stable | deprecated
  default_enabled: true | false
  noise_risk: low | med | high
```

**Category** partitions the corpus by purpose:
- `inventory` — statements of fact ("this file uses AES"). Never
  suppressed, never baselined.
- `security` — findings the user should act on. Eligible for
  `--fail-on`, baseline suppression, and the filter flags below.

**Maturity** describes readiness:
- `experimental` — default-off. Opt in with `--include-experimental` or
  per-rule `--include-rule <id>`. No deprecation timeline promised.
- `stable` — runs by default. Covered by the deprecation policy below.
- `deprecated` — still runs (so users see the warning) but emits an
  aggregated stderr warning and will be removed in the timeline below.

**default_enabled** lets rule authors opt a `stable` rule out of the
default scan (e.g. when a rule is sound but high-noise on typical
codebases). The filter engine re-includes such rules via `--include-noisy`,
`--include-rule`, or an explicit `--rules` allowlist.

**noise_risk** is informational — it drives the `--include-noisy` gate
and the `only-default-off` listing in `cradar rules list`.

### Deprecation timeline

A rule marked `maturity: deprecated` must:

1. Continue to run and produce findings.
2. Trigger an aggregated stderr warning naming the rule and pointing to
   ADR-035. The warning can be silenced with `--include-deprecated`.
3. Be removed no sooner than **two minor releases** after deprecation.

This mirrors Semgrep's rule-registry policy and matches CipherRadar's
release cadence (minor releases ~every 4–6 weeks) — giving users a 2- to
3-month window to migrate before a rule disappears.

### Forward-compat for older rules

Rules in the portal or in private rulesets that pre-date these fields
must keep working. `opengrep/parser.go` and `explain/explain.go` normalize
missing values to the permissive defaults:

| Field            | Default when absent |
|------------------|---------------------|
| `category`       | `security`          |
| `maturity`       | `stable`            |
| `noise_risk`     | `low`               |
| `default_enabled`| `true`              |

Pass 1 (tree-sitter) scanners currently emit findings without any
lifecycle metadata. The filter engine normalizes "empty Maturity" to the
same permissive defaults for decision-making so Pass 1 findings flow
through a default scan unchanged.

## Consequences

Positive:

- First-time scans surface only high-signal findings — noisy rules are
  opt-in, not opt-out.
- Rule authors can land detections as `experimental` and graduate them
  to `stable` once real-world signal is good.
- The `--fail-on` gate in CI becomes trustworthy: only `stable +
  default_enabled` rules can block a build by default.
- `cradar rules list` / `cradar rules explain` give users a browsable
  inventory of what the tool can detect, indexed by maturity.
- Baseline (.cradar-baseline.json) suppression is scoped to security
  findings and uses stable fingerprints (ADR-034), so acknowledged
  findings survive refactors and rule upgrades.

Trade-offs:

- Every rule file now carries four extra metadata fields. This is a
  one-time ~80-line annotation cost that's already paid (Phase B of the
  CLI improvements workstream).
- Portal-synced rules that omit these fields effectively become "runs by
  default" — organizations that want stricter defaults must set
  `rule_filters:` in `.cradar.yml` or pass explicit flags.
- The two-minor-release deprecation window pins us to a predictable
  release cadence; shipping a fast-fix for a truly broken rule still
  requires a point release within that window.

## Related decisions

- ADR-033 — Pass 3 (Joern) removal, which triggered the rule-corpus
  audit that exposed the noise problem.
- ADR-034 — Finding identity / stable fingerprints, which make baseline
  suppression survive reruns.
- ADR-025 — `.cradar.yml` configuration file, extended here with a
  `rule_filters:` block so defaults are per-repo, not per-CI-invocation.
