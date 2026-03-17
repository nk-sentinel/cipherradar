# ADR-007: Communications Design — Channels, Triggers, Notification Routing

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-16 |
| **Deciders** | Design session |
| **Supersedes** | — |
| **Superseded by** | — |

---

## Context

CipherRadar generates security findings, policy violations, certificate expiry warnings, and compliance events that must reach the right people at the right time. Without a defined communication model, notifications either go to everyone (noise) or to no one (findings ignored). The product serves multiple personas who need different information via different channels.

## Decision

Implement a scoped notification system with:
- **In-scope channels (Phase 1–3):** In-app, Email, Microsoft Teams, Jira, Developer-facing (CLI, pre-commit hook, VS Code, IntelliJ, PR/MR comments)
- **Deferred channels (Phase 4+):** Slack, Generic Webhook, GitHub/GitLab native, Linear, PagerDuty/OpsGenie
- **SMS dropped entirely**
- **Recipient model:** Security-side recipients (Security Engineer, Security Manager) + Scoped Developers (Developer-role users on the project) + Project Notification Contact (configurable email alias per project)
- **Three-level configuration:** Org defaults → Group overrides → User preferences
- **Jira integration:** One-way (Phase 3); bi-directional (Phase 4)

## Rationale

- In-app + Email + Teams covers all security team communication needs for Phase 1–3 without adding Slack as a second chat channel integration
- Project Notification Contact (email alias) solves the "app team" notification problem without requiring every developer to have a CipherRadar account
- Scoped Developers automatically receive notifications for their own projects — no manual subscription required
- SMS dropped: email + Teams provides urgency coverage with better formatting and no telephony dependency
- Jira one-way in Phase 3: bi-directional sync requires webhook listener + state reconciliation — too complex for Phase 3; deferred to Phase 4
- PagerDuty/OpsGenie in Phase 4: meaningful only for orgs with mature SOC and on-call rotation — a Phase 4 audience

## Consequences

- **Positive:** Developers get notified via their workflow (IDE, PR, CLI) without needing to monitor a separate dashboard
- **Positive:** Security teams get structured, severity-filtered notifications via Teams and email
- **Positive:** Project Notification Contact decouples team-level alerting from individual user accounts
- **Negative:** No Slack in Phase 3 — organisations that use Slack over Teams must wait for Phase 4
- **Negative:** One-way Jira means resolving a Jira ticket does not automatically close the finding — manual step until Phase 4

## Alternatives Considered and Rejected

| Option | Reason Rejected |
|---|---|
| Include Slack in Phase 3 | Teams covers the chat channel use case; maintaining two similar integrations in Phase 3 splits effort |
| SMS for certificate expiry | Telephony dependency; no formatting; email + Teams sufficient for the urgency level |
| Bi-directional Jira in Phase 3 | Requires webhook listener + state reconciliation; too complex; deferred to Phase 4 |
| PagerDuty in Phase 3 | Enterprise on-call tooling; Phase 4 audience; in-scope channels sufficient for Phase 3 |

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/10-communications.md` | New document created to detail the full communications design |
| `docs/04-features.md` | Feature Set 7 (CI/CD & Developer Integration) partially describes notification channels — should be read alongside 10-communications.md |
