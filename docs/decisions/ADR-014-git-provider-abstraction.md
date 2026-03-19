# ADR-014: Git Provider Abstraction — Common Interface for GitHub/GitLab/Bitbucket

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-19 |
| **Deciders** | Architecture session |

---

## Context

The backend must integrate with GitHub, GitLab, and Bitbucket (Cloud + Data Center) for OAuth login, webhook reception, and PR/MR annotations. Each provider has a different API surface, authentication flow, webhook signature format, and concept model (e.g., GitHub "Checks" vs. GitLab "Commit Statuses" vs. Bitbucket "Build Statuses"). Without an abstraction layer, provider-specific code would leak into business logic throughout the codebase.

---

## Decision

A common `GitProvider` protocol abstracts all provider-specific operations behind a single interface:

```python
class GitProvider(Protocol):
    async def authenticate(self, code: str) -> OAuthToken: ...
    async def list_repos(self, token: OAuthToken) -> list[Repository]: ...
    async def create_webhook(self, repo: Repository, url: str, secret: str) -> Webhook: ...
    async def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool: ...
    async def post_check_status(self, repo: Repository, commit: str, status: CheckStatus) -> None: ...
    async def post_pr_comment(self, repo: Repository, pr_id: int, body: str) -> None: ...
```

### Implementations

| Class | Provider | Notes |
|---|---|---|
| `GitHubProvider` | GitHub (Cloud + Enterprise) | Uses GitHub Apps for auth; Checks API for status |
| `GitLabProvider` | GitLab (Cloud + Self-Managed) | Token-based webhook validation (no HMAC) |
| `BitbucketCloudProvider` | Bitbucket Cloud | Atlassian Connect; HMAC-SHA256 webhooks |
| `BitbucketDataCenterProvider` | Bitbucket Data Center (Server) | REST API v1; HMAC-SHA256 webhooks |

### Webhook Signature Verification

Webhook signature verification is **mandatory** for all providers — unsigned or unverified payloads are rejected:

| Provider | Verification Method |
|---|---|
| GitHub | HMAC-SHA256 (`X-Hub-Signature-256` header) |
| GitLab | Secret token comparison (`X-Gitlab-Token` header) |
| Bitbucket Cloud | HMAC-SHA256 (`X-Hub-Signature` header) |
| Bitbucket Data Center | HMAC-SHA256 (`X-Hub-Signature` header) |

### Provider Resolution

The provider implementation is resolved at runtime based on the integration record stored per project. A factory function maps the stored provider type to the correct implementation class.

---

## Rationale

A protocol-based abstraction keeps business logic (scan triggering, result annotation, status reporting) completely decoupled from provider-specific API details. Adding a new provider (e.g., Azure DevOps, Gitea) requires implementing one interface — no changes to scan orchestration, webhook routing, or notification logic.

The interface is intentionally kept to the **minimum common denominator** of operations needed for CipherRadar's integration points: OAuth, repo listing, webhooks, status checks, and PR comments. Provider-specific features (e.g., GitHub's rich Checks API with annotations) can be exposed via optional extension methods on the concrete class, but the core business logic only calls the protocol methods.

---

## Consequences

- **Positive:** New git providers can be added by implementing a single interface — no changes to business logic
- **Positive:** Business logic never touches provider-specific APIs directly
- **Positive:** Webhook signature verification enforced uniformly across all providers
- **Positive:** Testable — mock implementations trivial to create for unit tests
- **Negative:** Lowest-common-denominator interface means richer provider features (e.g., GitHub Checks annotations) require optional extensions outside the core protocol
- **Negative:** Bitbucket Data Center's older REST API may require additional workarounds within the implementation

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/12-phase2-implementation-plan.md` | B-M3 milestone: git provider integration scope and interface defined |
