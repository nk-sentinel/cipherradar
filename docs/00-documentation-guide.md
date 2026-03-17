# Documentation Guide

> **Document version:** v1
> **Created:** 2026-03-17
> **Status:** Active
> **Purpose:** Governs how all documentation in this project is created, structured, versioned, updated, and maintained.

This is the root reference for documentation standards. All contributors must follow these rules when creating or modifying any document in `docs/`.

---

## 1. Document Types

| Type | Location | Naming | Purpose |
|---|---|---|---|
| **Design Document** | `docs/` | `NN-kebab-case.md` | Describes what the system is, how it works, and design decisions for a specific domain |
| **Architecture Decision Record** | `docs/decisions/` | `ADR-NNN-kebab-case.md` | Immutable record of a significant architectural or design decision |
| **Decision Log** | `docs/DECISION-LOG.md` | Fixed name | Master index of all ADRs and all open questions across the project |
| **Documentation Guide** | `docs/` | `00-documentation-guide.md` | This document — governs documentation standards |

---

## 2. File Naming Rules

### Design Documents
- Two-digit numeric prefix, zero-padded: `01`, `02`, ... `10`, `11`
- Followed by a kebab-case descriptor
- All lowercase
- Examples: `01-product-design.md`, `09-rbac.md`, `10-communications.md`
- When adding a new document, use the next available number
- Numbers are permanent — do not renumber existing documents

### Architecture Decision Records
- Prefix: `ADR-` followed by a three-digit number, zero-padded: `ADR-001`, `ADR-002`
- Followed by a kebab-case descriptor of the decision topic
- Examples: `ADR-001-output-format.md`, `ADR-004-taint-engine-revision.md`
- Numbers are permanent and sequential — never reuse a number

### Special Files
- `DECISION-LOG.md` — always uppercase, always at `docs/` root
- `README.md` — always uppercase, project root or `docs/` root

---

## 3. Design Document Structure

Every design document must include the following in order:

### 3.1 Required Header

```markdown
# [Document Title]

> **Document version:** vN
> **Created:** YYYY-MM-DD
> **Last updated:** YYYY-MM-DD
> **Status:** Draft | Active | Superseded
> **Superseded by:** [link] (only if Status = Superseded)
```

### 3.2 Change History Table

Required once a document has been updated more than once. Placed immediately after the header, before the first section.

```markdown
## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | YYYY-MM-DD | Initial document | — |
| v2 | YYYY-MM-DD | [What changed and why] | [ADR-NNN or decision reference] |
```

### 3.3 Section Numbering

- Top-level sections: `## 1.`, `## 2.`, `## 3.`
- Sub-sections: `### 1.1`, `### 1.2`
- Sub-sub-sections: `#### 1.1.1`, `#### 1.1.2`
- Section numbers must be consistent — if a section is added or removed, renumber all affected sections in the same document
- Sub-section numbers must always match their parent — `### 3.2` belongs under `## 3.`, never under `## 2.`

### 3.4 Open Items Section

If a document has unresolved design questions, they must be tracked in a final section titled **Open Items**:

```markdown
## N. Open Items

| # | Question | Status |
|---|---|---|
| OQ-XXX-1 | [Question text] | Open / Resolved / Deferred / Dropped |
```

- Use the document prefix for the OQ code: `OQ-RBAC-1`, `OQ-COMM-1`, `OQ-ARCH-1`
- Also add all open questions to `DECISION-LOG.md`
- When resolved, update status in both places — never delete the row

---

## 4. ADR Structure

Every ADR must include the following sections in order:

```markdown
# ADR-NNN: [Short Decision Title]

| Field | Value |
|---|---|
| **Status** | Proposed | Accepted | Superseded | Deprecated |
| **Date** | YYYY-MM-DD |
| **Deciders** | [Who made this decision] |
| **Supersedes** | [ADR-NNN] (if applicable) |
| **Superseded by** | [ADR-NNN] (if applicable) |

---

## Context
[Why this decision was needed. What problem it solves. What constraints existed.]

## Decision
[The decision made. One clear, unambiguous statement.]

## Rationale
[Why this option was chosen over alternatives. Evidence, analysis, trade-offs.]

## Consequences
- **Positive:** [Benefits]
- **Negative:** [Costs or risks introduced]

## Alternatives Considered and Rejected

| Option | Reason Rejected |
|---|---|
| [Option A] | [Why not chosen] |

## Impact on Other Documents

| Document | What Changes |
|---|---|
| [doc name] | [What needs updating] |
```

---

## 5. ADR Lifecycle

### Statuses

| Status | Meaning |
|---|---|
| **Proposed** | Under discussion; not yet ratified |
| **Accepted** | Current standing decision; in effect |
| **Superseded** | Replaced by a newer ADR; kept for history |
| **Deprecated** | No longer relevant; context has changed |

### Rules

- ADRs are **immutable once Accepted** — never edit the content of an Accepted ADR
- To change a decision: create a new ADR that references the old one; mark the old ADR as Superseded
- Superseded ADRs are **never deleted** — they form the decision history
- Every ADR must be indexed in `DECISION-LOG.md` on the day it is created

---

## 6. Versioning Rules

### Design Documents

- Version numbers are integers: `v1`, `v2`, `v3` — no semantic versioning
- Increment the version for any **meaningful content change**:
  - New sections added
  - Existing decisions changed or expanded
  - Structural reorganisation
- Do **not** increment version for: typo fixes, formatting corrections, link repairs
- Every version increment requires:
  1. Update the `Document version` in the header
  2. Update `Last updated` date
  3. Add a row to the Change History table with what changed and what triggered it

### ADRs

- ADRs are not versioned — they are immutable
- Changes to decisions always produce a new ADR

---

## 7. Writing Style

| Rule | Example |
|---|---|
| **Present tense** for current state | "The scanner uses tree-sitter" not "The scanner will use tree-sitter" |
| **Future tense only** for roadmap items | "Phase 3 will add container scanning" |
| **Active voice** | "The policy engine evaluates rules" not "Rules are evaluated by the policy engine" |
| **Definitive statements** | "The system does X" not "The system may do X" or "we could do X" |
| **No marketing language** | Avoid superlatives, buzzwords, and vague claims |
| **Refer to the product as "CipherRadar"** | Not "we", "the tool", "the platform" (use specific names) |
| **Tables for comparisons and options** | Don't bury option comparisons in prose paragraphs |
| **Prose for rationale and context** | Don't reduce reasoning to a bullet point |
| **One idea per sentence** | Long compound sentences obscure meaning |

---

## 8. File Size Rules

### 8.1 Limits by Document Type

| Document Type | Soft Warning | Hard Limit | Action at Hard Limit |
|---|---|---|---|
| **ADR** | 150 lines | 200 lines | Extract detailed analysis to a companion appendix (`ADR-NNN-appendix-*.md`); keep ADR as the decision record |
| **Design document** | 400 lines | 600 lines | Split into sub-documents; keep parent as an overview with links |
| **Reference document** (tables, matrices) | 500 lines | 700 lines | Split by topic area |
| **Decision Log** | No limit | No limit | Append-only; grows by design |
| **Documentation Guide** | No limit | No limit | Reference document |

### 8.2 Split Signals

Split a document when any of these are true — regardless of total line count:

- A single section exceeds **100 lines** on its own
- The document covers more than one distinct audience
- A section is referenced independently more often than the parent document
- The document has reached its hard limit

### 8.3 How to Split a Design Document

Keep the parent document as an **overview with links** to child documents. Use the parent number with a letter suffix for children:

```
02-architecture.md              ← Overview, diagrams, deployment models
02a-architecture-graph-db.md    ← Graph DB detail (split out when section grew)
02b-architecture-scanning.md    ← Scanning pipeline detail
```

Update the parent's Change History when a split occurs. Add a note at the top of the split section in the parent pointing to the child doc.

### 8.4 ADR Companion Appendix

When an ADR's supporting analysis exceeds the line limit, extract it to a named appendix file in `docs/decisions/`:

```
ADR-NNN-topic.md                   ← The decision record (under 150 lines)
ADR-NNN-appendix-analysis.md       ← Supporting analysis, tables, benchmarks
```

The ADR must reference the appendix explicitly: *"See [appendix](ADR-NNN-appendix-analysis.md) for full feasibility analysis."*

---

## 9. Cross-Referencing Rules

- Always use **relative paths** for links between docs: `[RBAC](09-rbac.md)`, `[ADR-004](decisions/ADR-004-taint-engine-revision.md)`
- When a design doc is updated because of an ADR, note it in the Change History: `Triggered By: ADR-004`
- When creating an ADR that affects other docs, list all affected docs in the "Impact on Other Documents" section
- When referencing an open question from one doc in another, use the full OQ code: `OQ-RBAC-5`

---

## 9. Open Questions Management

### Raising a Question

1. Add it to the relevant design doc's **Open Items** section with a unique OQ code
2. Add it to `DECISION-LOG.md` Open Questions table simultaneously
3. Use format: `OQ-[DOC-PREFIX]-[N]` — e.g., `OQ-RBAC-5`, `OQ-COMM-3`, `OQ-ARCH-1`

### Resolving a Question

1. Update status in the design doc's Open Items section: `Open` → `Resolved` / `Deferred` / `Dropped`
2. Add the resolution decision in the status cell
3. Mirror the update in `DECISION-LOG.md`
4. If the resolution requires changes to the document body, update the body and increment the document version
5. Never delete a resolved question row — the resolution history is valuable

### Question Statuses

| Status | Meaning |
|---|---|
| **Open** | Unresolved; needs a decision |
| **Resolved** | Decision made; documented |
| **Deferred** | Intentionally postponed to a future phase or milestone |
| **Dropped** | No longer relevant; context has changed |
| **Closed** | Not applicable to this project |

---

## 10. Document Lifecycle

### Creating a New Document

1. Assign the next available number
2. Add the required header with `Status: Draft`
3. Add a row to `DECISION-LOG.md` ADR index (for ADRs) or note it in meeting notes
4. Change status to `Active` when the document is reviewed and considered complete enough to act on

### Updating a Document

1. Edit the content
2. Increment the version number in the header
3. Update `Last updated` date
4. Add a row to the Change History table
5. If the update was triggered by an ADR or a resolved OQ, reference it in the Change History

### Superseding a Document

1. Create the replacement document or ADR
2. Add `Status: Superseded` and `Superseded by: [link]` to the old document's header
3. Never delete the superseded document

### Deprecating a Document

1. Change `Status` to `Deprecated` in the header
2. Add a note at the top of the document explaining why it is deprecated and what replaced it

---

## 11. DECISION-LOG.md Rules

`DECISION-LOG.md` is the **single source of truth** for:
- The index of all ADRs (title, status, date, affected docs)
- The full list of all open questions across all documents
- The timeline of key decisions and changes

### Rules

- Every ADR must be added to the index table on the day it is created
- Every open question must be added when raised, not retrospectively
- Resolved questions are updated in-place — never removed
- The timeline section is append-only — add new entries; never edit past entries
- The lessons learned section is append-only

---

## 12. Current Document Index

| # | Document | Version | Status | Domain |
|---|---|---|---|---|
| [00](00-documentation-guide.md) | Documentation Guide | v1 | Active | Meta |
| [01](01-product-design.md) | Product Design | v1 | Active | Product |
| [02](02-architecture.md) | Architecture | v1 | Active | Architecture |
| [03](03-detection-engine.md) | Detection Engine | v2 | Active | Scanning |
| [04](04-features.md) | Features | v1 | Active | Product |
| [05](05-compliance.md) | Compliance | v1 | Active | Compliance |
| [06](06-data-model.md) | Data Model | v1 | Active | Data |
| [07](07-tech-stack.md) | Tech Stack | v2 | Active | Architecture |
| [08](08-roadmap.md) | Roadmap | v2 | Active | Planning |
| [09](09-rbac.md) | RBAC | v1 | Active | Security |
| [10](10-communications.md) | Communications | v1 | Active | Product |
| — | [DECISION-LOG](DECISION-LOG.md) | — | Active | Governance |
| — | [ADR-001](decisions/ADR-001-output-format.md) | — | Accepted | Architecture |
| — | [ADR-002](decisions/ADR-002-parsing-backbone.md) | — | Accepted | Architecture |
| — | [ADR-003](decisions/ADR-003-codeql-independence.md) | — | Accepted | Architecture |
| — | [ADR-004](decisions/ADR-004-taint-engine-revision.md) | — | Accepted | Architecture |
| — | [ADR-005](decisions/ADR-005-cli-language-and-deployment.md) | — | Accepted | Architecture |
| — | ADR-006 (file pending) | — | Accepted | Security |
| — | ADR-007 (file pending) | — | Accepted | Product |

---

## 13. Known Issues to Fix (Backlog)

The following inconsistencies exist in current documents and should be corrected:

| # | Document | Issue |
|---|---|---|
| I-001 | `09-rbac.md` | Section 9 "API Key Management" has sub-sections numbered 8.1–8.4; sub-section numbers must match parent section |
| I-002 | `09-rbac.md` | Two sections numbered `## 10.` (Authentication Methods and Multi-Tenancy); one must be renumbered |
| I-003 | `09-rbac.md` | Missing `Created`, `Last updated`, `Status` fields in header |
| I-004 | `10-communications.md` | Missing `Last updated`, `Status` fields in header |
| I-005 | `02-architecture.md` | Missing version header entirely |
| I-006 | `04-features.md` | Missing version header entirely |
| I-007 | `05-compliance.md` | Missing version header entirely |
| I-008 | `06-data-model.md` | Missing version header entirely |
| I-009 | `DECISION-LOG.md` | ADR-006 and ADR-007 are indexed but their files do not exist in `docs/decisions/` |
| I-010 | All ADRs | Missing "Impact on Other Documents" section |
