# Communications & Notifications

> **Document version:** v1
> **Created:** 2026-03-16
> **Last updated:** 2026-03-17
> **Status:** Active

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-16 | Initial document | ADR-007 |

---

## 1. Overview

CipherRadar communicates with users and teams through a set of notification channels. Channels are split into two tiers:

| Tier | Channels | Delivery |
|---|---|---|
| **In-scope (Phase 1–3)** | In-app, Email, Microsoft Teams, Jira, Developer-facing | Implemented per phase |
| **Future (Phase 4+)** | Slack, Generic Webhook, GitHub/GitLab native, Linear, PagerDuty/OpsGenie | Deferred |

---

## 2. Notification Recipients

### 2.1 Recipient Types

Every notification is routed to one or more of the following recipient types:

| Recipient Type | Who It Is |
|---|---|
| **Security Manager** | User(s) with Security Manager role at org level |
| **Security Engineer** | User(s) with Security Engineer role scoped to the affected project or its parent group |
| **Compliance Auditor** | User(s) with Compliance Auditor role at org level |
| **Scoped Developers** | All users with Developer role assigned to the affected project or its parent group |
| **Project Notification Contact** | A configurable email alias per project (e.g., `backend-team@company.com`) — covers the whole app team regardless of individual CipherRadar accounts |
| **Scan Requester** | The user or CI/CD service account that triggered the scan |
| **Key Creator** | The user who created a specific API key |

### 2.2 Project Notification Contact

Each project has a **Notification Contact** field — a free-text email address, typically a team distribution list. This ensures the entire application team receives project-level alerts even if individual team members are not registered in CipherRadar.

- Set by: Security Engineer or Org Admin on the project settings page
- Accepts: single email address or distribution list alias
- Receives: all project-level notifications (findings, violations, cert expiry, scan results)
- Independent of RBAC — a purely notification-routing field

---

## 3. Notification Triggers

| # | Trigger | Severity | Recipients |
|---|---|---|---|
| T-01 | Scan completed (no violations) | Info | Scan Requester, Scoped Developers, Project Notification Contact |
| T-02 | Scan completed with policy violations | High | Security Engineer, Security Manager, Scoped Developers, Project Notification Contact |
| T-03 | New Critical finding detected | Critical | Security Engineer, Security Manager, Scoped Developers, Project Notification Contact |
| T-04 | New quantum-vulnerable algorithm found | High | Security Manager, Security Engineer, Scoped Developers, Project Notification Contact |
| T-05 | Policy FAIL on main / release branch | Critical | Security Engineer, Security Manager, Scoped Developers, Project Notification Contact |
| T-06 | Certificate expiring ≤ 30 days | High | Security Engineer, Security Manager, Scoped Developers, Project Notification Contact |
| T-07 | Certificate expiring ≤ 7 days | Critical | Security Engineer, Security Manager, Scoped Developers, Project Notification Contact |
| T-08 | Certificate expired | Critical | Security Engineer, Security Manager, Org Admin, Scoped Developers, Project Notification Contact |
| T-09 | Compliance score dropped below threshold | High | Security Manager, Compliance Auditor |
| T-10 | CBOM diff — new findings vs. last scan | Medium | Security Engineer, Scoped Developers, Project Notification Contact |
| T-11 | New CVE published for a detected crypto library | Critical | Security Manager, Security Engineer, Scoped Developers, Project Notification Contact |
| T-12 | Suppression request raised | Info | Security Engineer (approver) |
| T-13 | Suppression request approved | Info | Developer (requester), Project Notification Contact |
| T-14 | Suppression request rejected | Info | Developer (requester) |
| T-15 | Suppression expired — finding re-opened | Medium | Security Engineer, Scoped Developers, Project Notification Contact |
| T-16 | API key expiring in 7 days | Info | Key Creator |
| T-17 | Scan failed / error | Medium | Scan Requester, Org Admin |

---

## 4. In-Scope Channels

### 4.1 In-App (Dashboard)

| Component | Behaviour |
|---|---|
| Notification bell | Count badge on all dashboard pages; clears on open |
| Notification centre | Full event list with read/unread state, severity badge, timestamp, direct link to finding or scan |
| Toast alerts | Transient banners for real-time events while the user is active in the dashboard; auto-dismiss after 5 seconds for Info/Medium; persist until dismissed for High/Critical |

Notification centre is scoped to the user's access — users only see notifications for projects and groups they have access to.

---

### 4.2 Email

| Aspect | Detail |
|---|---|
| Delivery modes | Immediate (per event) or Digest (daily / weekly — user choice per event type) |
| Format | HTML template with severity colour band + plain-text fallback |
| Content | Event summary, severity, affected project, file:line (where applicable), direct link to dashboard |
| Scoping | User receives only emails for projects/groups within their access scope |
| Transactional emails | Account invite, password reset, API key expiry warning, suppression request decisions |
| Unsubscribe | Per event type via email footer link; in-app notifications remain active regardless |
| Distribution lists | Project Notification Contact email alias receives project-level triggers (T-01 to T-11, T-13, T-15) |

**Digest format:** One email summarising all events in the period, grouped by project, sorted by severity. Includes counts and a link to the full dashboard view.

---

### 4.3 Microsoft Teams

| Aspect | Detail |
|---|---|
| Integration method | Teams App (OAuth) or Incoming Webhook URL |
| Message format | Adaptive Cards — severity colour band, event summary, affected project + file, action buttons |
| Action buttons | View Finding (link to dashboard) / Create Jira Ticket (if Jira connected) |
| Configurable per channel | Choose which event types and minimum severity threshold to post |
| Scope | Can be scoped to org-wide, specific group, or specific project |
| Deduplication | Same finding does not post again until resolved and re-triggered |

**Adaptive Card structure:**
```
┌─────────────────────────────────────────┐
│ 🔴 CRITICAL — New Finding               │
│ Project: auth-service                   │
│ Algorithm: RSA-1024                     │
│ File: src/crypto/KeyManager.java:42     │
│ Quantum Status: quantum-vulnerable      │
│ Policy: MIN_KEY_SIZE violated           │
│                                         │
│ [View Finding]  [Create Jira Ticket]    │
└─────────────────────────────────────────┘
```

---

### 4.4 Jira

| Aspect | Detail |
|---|---|
| Trigger events | T-02 (policy violation), T-03 (Critical finding), T-05 (policy FAIL on main branch), T-07/T-08 (cert expiry/expired), T-11 (CVE on crypto library) |
| Issue type | Configurable per project — Bug / Security Vulnerability / Task |
| Deduplication | Checks for an existing open ticket for the same finding ID before creating — no duplicates |
| Sync direction | **One-way (Phase 3):** CipherRadar → Jira only |
| Pre-filled fields | Summary, description (finding detail + code location + remediation guidance), severity, CWE, OWASP reference, file:line, labels (`cbom`, `crypto`, severity level) |
| Assignee | Auto-assigned to the group/team mapped to the project (configurable) |
| Project mapping | Each CipherRadar project maps to a configured Jira project key |
| Bi-directional sync | **Phase 4** — when Jira issue is resolved, finding flagged for suppression review in CipherRadar |

**Auto-generated Jira ticket description format:**
```
h2. Finding Summary
Algorithm: RSA-1024
File: src/crypto/KeyManager.java, Line 42
Quantum Status: quantum-vulnerable
Policy Violated: MIN_KEY_SIZE (minimum 2048 bits required)

h2. Risk
NIST IR 8547: RSA-1024 deprecated by 2030, disallowed by 2035.
CWE-326: Inadequate Encryption Strength

h2. Remediation
Replace RSA-1024 with RSA-2048 or migrate to ML-KEM-768 (NIST PQC Level 3).
See: [CipherRadar Finding →]

h2. References
- NIST SP 800-131A Rev.3
- CWE-326
- OWASP Cryptographic Failures (A02:2021)
```

---

### 4.5 Developer-Facing Channels

#### CLI Terminal Output

Displayed on every `cbom scan` run:

```
CipherRadar v1.0.0  |  Scanning: auth-service

  [CRITICAL]  RSA-1024 detected  →  src/crypto/KeyManager.java:42
              quantum-vulnerable · Policy FAIL: MIN_KEY_SIZE
              CWE-326 · Fix: upgrade to RSA-2048 or ML-KEM-768

  [HIGH]      AES-128-CBC detected (no MAC)  →  src/utils/Encryptor.java:87
              unauthenticated encryption · Policy WARN
              Fix: use AES-256-GCM

  Summary: 2 findings  |  1 CRITICAL  1 HIGH  |  Policy: FAIL
  CBOM written to: cbom.json
  Exit code: 1
```

Colour-coded by severity. Exit code 1 on FAIL, 0 on PASS — enables CI/CD gate behaviour.

---

#### Pre-Commit Hook

Lightweight fast-path scan (regex layer only — no tree-sitter, no Semgrep) that runs before every `git commit`:

```
CipherRadar pre-commit check...

  ✗ Hardcoded key detected:
    src/config/secrets.py:14  →  AES_KEY = "a3f1b2c4d5e6f7a8..."
    Commit blocked. Remove or rotate the key before committing.

  Run `cbom scan` for full analysis.
```

Blocks the commit if a hardcoded key, PEM block, or known secret pattern is found. Only the fast regex layer runs — no performance impact on commit workflow.

---

#### VS Code Extension

| Feature | Detail |
|---|---|
| Inline annotation | Squiggly underline on crypto API calls with findings |
| Hover card | Shows algorithm name, key size, quantum status, policy compliance, fix suggestion |
| Problems panel | All findings listed with severity, file, line — clickable to navigate |
| Severity icons | Gutter icons (🔴 Critical, 🟠 High, 🟡 Medium) |
| Trigger | On file save (fast scan); full scan on demand via command palette |

---

#### IntelliJ / JetBrains Plugin

| Feature | Detail |
|---|---|
| Line annotation | Gutter icon + line highlight on crypto calls with findings |
| Inspection tooltip | Hover shows finding detail + remediation |
| Inspection panel | All findings in the standard IntelliJ inspection results panel |
| Severity mapping | Maps to IntelliJ severity levels (Error / Warning / Weak Warning) |
| Trigger | On file save; full project scan via right-click menu |

---

#### PR / MR Comments (GitHub / GitLab)

Posted automatically on PR open and on each new push to the PR branch:

- Shows only **new findings introduced by this PR** (diff vs. base branch)
- Table format: severity, algorithm, file:line, quantum status, policy result
- Inline comment posted at the exact diff line where the finding occurs
- Summary comment on the PR with total finding count and policy result (PASS / FAIL)
- If no new findings: a single green ✓ comment confirming no new crypto issues introduced

---

## 5. Notification Configuration Model

Notifications are configured at three levels. Settings cascade downward; lower levels can narrow but not expand what the level above has configured.

```
Org-level defaults
  (set by Org Admin / Security Manager — applies to all projects)
 └── Group-level overrides
       (set by Security Engineer — applies to projects in that group)
      └── User-level preferences
            (each user's own subscribe/unsubscribe and cadence choices)
```

### Per Notification Rule Configuration

| Setting | Options |
|---|---|
| Event types | Select one or more triggers from the trigger list |
| Minimum severity | Info / Medium / High / Critical |
| Channel | In-app / Email / Teams channel / Jira project |
| Scope | Org-wide / Specific group / Specific project |
| Cadence | Immediate / Hourly digest / Daily digest / Weekly digest |

### User-Level Preferences

Each user can:
- Subscribe or unsubscribe from individual event types
- Switch between immediate and digest delivery per event type
- Mute notifications for a project temporarily (snooze — configurable duration)
- Cannot subscribe to events for projects outside their access scope

---

## 6. Deferred Channels (Phase 4+)

The following channels are out of scope for Phase 1–3 and documented here for future reference:

| Channel | Reason Deferred | Notes for Phase 4 |
|---|---|---|
| **Slack** | Teams covers the chat channel use case for Phase 3 | Block Kit cards; per-channel configurable; slash command `/cbom status` |
| **Generic Outbound Webhook** | Custom integrations are a Phase 4 enterprise differentiator | HMAC-signed JSON; single-event default; optional scan-level batching |
| **GitHub native** (Checks API, Security Tab) | Covered by PR comments for Phase 3; full GitHub App is Phase 4 | SARIF upload to Code Scanning API; Checks pass/fail |
| **GitLab native** (Security Dashboard) | MR comments cover Phase 3; full integration in Phase 4 | SARIF upload to GitLab vulnerability dashboard |
| **Linear** | Jira covers ticket creation for Phase 3 | Same model as Jira |
| **PagerDuty / OpsGenie** | Enterprise on-call integration; Phase 4 audience | Events API v2; auto-resolve on finding remediation |
| **SMS** | Dropped — email + Teams covers urgency; SMS adds telephony dependency with no formatting benefit | — |

---

## 7. Open Questions

| # | Question | Status |
|---|---|---|
| OQ-COMM-1 | Should SMS be supported for certificate expiry alerts? | **Dropped** — email + Teams sufficient; SMS adds cost and complexity with no formatting benefit |
| OQ-COMM-2 | PagerDuty/OpsGenie — Phase 3 or Phase 4? | **Resolved** — Phase 4; in-scope channels cover Phase 3 enterprise needs |
| OQ-COMM-3 | Webhook — single event or batched payload? | **Deferred with recommendation** — single-event default; optional scan-level batching when implemented in Phase 4 |
| OQ-COMM-4 | Bi-directional Jira sync — Phase 3 or Phase 4? | **Resolved** — Phase 3 is one-way (CipherRadar → Jira); bi-directional sync in Phase 4 |
