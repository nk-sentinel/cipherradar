# ADR-025: CLI-to-Portal Push Model

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-20 |
| **Deciders** | Architecture session |
| **Related** | ADR-024 (CLI binary rename), ADR-013 (authentication model) |

---

## Context

The CLI can scan locally and produce output files (CycloneDX JSON, SARIF, PDF, text), but there is no mechanism to push results to the CipherRadar portal. Users need to upload scan results from CI/CD pipelines and local development environments to centralize findings, track trends, and enforce compliance at the portfolio level.

Without a push mechanism, users must either:
1. Manually upload CBOM files through the web dashboard
2. Write custom scripts to call the backend API
3. Use only the local CLI output without portal integration

None of these provide the single-command CI/CD experience expected of a modern security scanner.

---

## Decision

Add a combined scan + push workflow via a `--push` flag on the `cradar scan` command.

### CLI Usage

```bash
cradar scan ./project \
  --push \
  --project "payment-service" \
  --group "Engineering/Backend" \
  --api-url https://cipherradar.company.com/api/v1 \
  --api-key $CRADAR_API_KEY
```

### Design

1. **`--push` flag** triggers upload after scan completes successfully
2. **`--project`** (required with `--push`) identifies the target project by name within the authenticated user's organisation
3. **`--group`** (optional) specifies the group path; falls back to the user's default group if omitted
4. **API key** provides authentication and organisation context (per ADR-013 scoped API key model)
5. **Config file** `.cradar.yml` can store defaults (`api_url`, `project`, `group`) to reduce CLI flag verbosity

### Config File Example

```yaml
# .cradar.yml (project root or ~/.cradar/config.yml)
api_url: https://cipherradar.company.com/api/v1
project: payment-service
group: Engineering/Backend
```

When both config file and CLI flags are provided, CLI flags take precedence.

### Backend Endpoint

**`POST /api/v1/scans/upload`**

Request:
- Body: CycloneDX 1.7 JSON
- Headers: `Authorization: Bearer <api_key>`, `Content-Type: application/vnd.cyclonedx+json`
- Query/body params: `project_name`, `group_path` (optional), `branch`, `commit_sha`

Response:
- `201 Created` — scan created, returns scan ID and project ID
- `401 Unauthorized` — invalid or missing API key
- `404 Not Found` — project not found and user lacks `project:write` permission
- `422 Unprocessable Entity` — invalid CBOM JSON

### Project Resolution

| Condition | Behavior |
|---|---|
| Project found by name within user's org | Create scan under existing project |
| Project not found + user has `project:write` | Auto-create project under specified/default group |
| Project not found + user lacks `project:write` | Return `404 Not Found` |

Auto-creation reduces setup friction for new projects — the first `cradar scan --push` from a CI pipeline creates the project automatically if the API key has sufficient permissions.

### Group Resolution (Security-Safe)

| Condition | Behavior |
|---|---|
| Group found + user has access | Use specified group |
| Group not found OR user lacks access | Fall back to user's default group + print **WARNING** |

The warning message is **identical** for both "group not found" and "group exists but user lacks access" cases. This prevents information leakage about group existence — the same pattern GitHub uses (404-not-403 for private repos).

Warning format:
```
WARNING: Group "Engineering/Backend" not available. Scan placed in default group "My Group".
```

---

## Rationale

### Combined scan + push (not separate upload command)

A single `cradar scan --push` command is the simplest CI/CD integration. A separate `cradar upload` command would work but adds a pipeline step and requires managing the intermediate CBOM file. The `--push` flag is additive — scan behavior is unchanged without it.

### Project auto-creation

Enterprise CI/CD pipelines scan hundreds of repositories. Requiring manual project creation in the portal before the first scan adds friction and discourages adoption. Auto-creation (gated by `project:write` permission) removes this barrier while maintaining access control.

### Group fallback with identical error messages

Silently placing a scan in the wrong group is a risk, but revealing group existence to users without access is a security concern. The identical warning message balances both: the user is clearly told their specified group was not used (preventing silent misplacement), while group existence is not leaked (preventing enumeration).

---

## Consequences

- **Positive:** Single command for scan + upload in CI/CD pipelines
- **Positive:** Config file (`.cradar.yml`) reduces CLI flag verbosity for repeated scans
- **Positive:** Auto-create reduces setup friction for new projects
- **Positive:** Group fallback prevents 403 information leakage about group existence
- **Negative:** Group fallback could silently place data in wrong group if user misconfigures group path (mitigated by clear WARNING message)
- **Negative:** Adds network dependency to scan command when `--push` is used (mitigated: push is opt-in)

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `CLAUDE.md` | Add `--push` flag to CLI commands section |
| `docs/13-phase3-implementation-plan.md` | A-M2 work description: `--push` flag + `.cradar.yml` config |
| `docs/13-phase3-implementation-plan.md` | B-M2 work description: `POST /api/v1/scans/upload` endpoint |
| `deploy/README.md` | Add push examples to CI/CD documentation |
| `deploy/github-action/action.yml` | Add `push`, `project`, `group`, `api-url`, `api-key` inputs |
| `deploy/gitlab-ci/cradar-scan.gitlab-ci.yml` | Add `CRADAR_PUSH`, `CRADAR_PROJECT`, `CRADAR_GROUP` variables |
