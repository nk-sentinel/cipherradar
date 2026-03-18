# ADR-009: OpenGrep Replaces Semgrep as the Pass 2 Engine

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-18 |
| **Deciders** | Architecture session |
| **Supersedes** | Semgrep reference in ADR-004 (approach unchanged; engine swapped) |

---

## Context

ADR-004 established a three-pass detection engine where Pass 2 uses Semgrep taint rules (YAML, per language) to cover ~8–10% of findings that Pass 1 (constant propagation) cannot resolve. The original ADR referenced Semgrep OSS (LGPL-2.1).

In December 2024, Semgrep Inc. moved critical features — including **taint analysis**, result fingerprinting, tracking ignores, and LOC metrics — behind a commercial licence, renaming the free tier "Community Edition" (CE). Simultaneously, the Semgrep Rules Registry was placed under a new **Semgrep Rules Licence v1.0** that prohibits use of Semgrep-maintained rules in SaaS products or competing tools.

In January 2025, a consortium of 10+ AppSec companies (Aikido, Endor Labs, Jit, Orca Security, Kodem, Mobb, and others) forked Semgrep v1.100.0 as **OpenGrep**, restoring the removed features under LGPL-2.1 and keeping rules under permissive licences.

---

## Decision

Use **OpenGrep** as the Pass 2 engine in place of Semgrep.

The three-pass detection architecture defined in ADR-004 is unchanged. Only the binary that executes Pass 2 YAML rules changes from `semgrep` to `opengrep`.

---

## Rationale

| Factor | OpenGrep | Semgrep CE |
|---|---|---|
| **Taint mode** | ✅ Fully restored, free | ❌ Moved to commercial tier |
| **YAML rule format** | ✅ Identical — all `scanner/rules/` compatible | ✅ Same |
| **Rules licence** | ✅ Permissive — SaaS and commercial use allowed | ❌ Semgrep Rules Licence v1.0 prohibits SaaS / competing products |
| **Binary size** | 28–41 MB (statically linked) | 42–61 MB (statically linked) |
| **Runtime dependencies** | None | None |
| **Maintenance** | Active — dedicated OCaml team from consortium | Active — Semgrep Inc. |
| **Taint languages (Pass 2)** | 12 languages (C, C++, Java, JS, TS, Go, Python, Ruby, PHP, C#, Kotlin, Lua) | Reduced in CE |

**Three decisive factors:**

1. **Taint mode is required, not optional.** Pass 2 is built on `mode: taint` YAML rules. Semgrep CE no longer provides taint mode for free. OpenGrep restores it under LGPL-2.1.

2. **Rule licence conflict.** If CipherRadar becomes a commercial or SaaS product (see deferred decision P-001), the Semgrep Rules Licence v1.0 would prohibit using any rules sourced from Semgrep's registry. Our `scanner/rules/` are self-authored, but inheriting the format from a restricted ecosystem creates legal risk. OpenGrep rules carry no such restriction.

3. **Binary compatibility.** All `scanner/rules/*.yml` files authored for Semgrep's YAML format run on OpenGrep without modification. Migration cost is zero.

---

## Alternatives Considered

**Keep Semgrep CE**
Rejected. Taint mode is no longer available in CE — the core requirement of Pass 2. Upgrading to Semgrep Pro would introduce a per-seat or per-scan commercial dependency into the open-source CLI, conflicting with ADR-003's principle of no mandatory third-party infrastructure.

**Semgrep Pro**
Rejected. Introduces a commercial dependency and account requirement for the CLI binary. Breaks the "single binary, no dependencies" principle (ADR-005).

**Write Pass 2 rules for an alternative engine (Joern only, CodeQL)**
Rejected. Joern is already Pass 3. Moving Pass 2 to Joern would collapse two distinct layers into one and lose the fast PR-time feedback that Pass 2 provides. CodeQL requires a build (violates ADR-003).

---

## Consequences

- **Positive:** Taint mode remains free and available in the CLI binary distribution
- **Positive:** No licence conflict if CipherRadar goes commercial
- **Positive:** Smaller binary (28–41 MB vs 42–61 MB)
- **Positive:** Zero rule migration cost — YAML format is identical
- **Negative:** OpenGrep has a smaller community (~2.2k stars vs 10k+) and is newer — higher risk of abandonment or slow fixes
- **Mitigation:** OpenGrep is backed by 10+ funded AppSec companies with a dedicated full-time OCaml team; the risk is lower than a solo community fork

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/07-tech-stack.md` | Replace "Semgrep OSS (LGPL)" with "OpenGrep (LGPL-2.1)" in Pass 2 entry; update rationale |
| `docs/03-detection-engine.md` | Update Pass 2 section to reference OpenGreep; note licence context |
| `docs/decisions/ADR-004-taint-engine-revision.md` | Add a note referencing ADR-009 for the engine swap |
