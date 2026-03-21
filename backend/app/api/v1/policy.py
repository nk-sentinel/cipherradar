from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.finding import Finding
from app.schemas.policy import PolicyRule, PolicyRuleListResponse, PolicyRuleToggle

router = APIRouter(prefix="/policy", tags=["policy"])


# ---------------------------------------------------------------------------
# Hardcoded policy rules from the CLI policy engine
# ---------------------------------------------------------------------------

_DEFAULT_RULES: list[dict[str, str]] = [
    {
        "id": "no-broken-algorithms",
        "name": "No Broken Algorithms",
        "description": "Disallow use of cryptographically broken algorithms (MD5, SHA-1, DES, RC4, etc.)",
        "severity": "critical",
    },
    {
        "id": "no-ecb-mode",
        "name": "No ECB Mode",
        "description": "Disallow ECB block cipher mode which leaks patterns in ciphertext",
        "severity": "high",
    },
    {
        "id": "rsa-min-key-size",
        "name": "RSA Minimum Key Size",
        "description": "Require RSA keys to be at least 2048 bits (recommend 4096)",
        "severity": "high",
    },
    {
        "id": "no-deprecated-tls",
        "name": "No Deprecated TLS",
        "description": "Disallow TLS 1.0 and TLS 1.1 which are deprecated",
        "severity": "high",
    },
    {
        "id": "quantum-vulnerable",
        "name": "Quantum Vulnerable",
        "description": "Flag algorithms vulnerable to quantum computing attacks (RSA, ECDSA, DH, etc.)",
        "severity": "medium",
    },
    {
        "id": "no-hardcoded-keys",
        "name": "No Hardcoded Keys",
        "description": "Disallow hardcoded cryptographic key material in source code",
        "severity": "critical",
    },
]

# Rule ID → set of rule_ids from findings that map to this policy rule
_RULE_FINDING_PATTERNS: dict[str, list[str]] = {
    "no-broken-algorithms": ["md5", "sha1", "sha-1", "des", "rc4", "rc2", "broken"],
    "no-ecb-mode": ["ecb"],
    "rsa-min-key-size": ["rsa"],
    "no-deprecated-tls": ["tls-1.0", "tls-1.1", "deprecated-tls", "tls1_0", "tls1_1"],
    "quantum-vulnerable": ["quantum"],
    "no-hardcoded-keys": ["hardcoded-key", "hardcoded_key", "hardcoded"],
}

# In-memory toggle state (persists within process lifetime)
_rule_enabled_state: dict[str, bool] = {rule["id"]: True for rule in _DEFAULT_RULES}


async def _count_violations_for_rule(
    session: AsyncSession,
    policy_rule_id: str,
) -> int:
    """Count findings whose rule_id matches the policy rule patterns."""
    patterns = _RULE_FINDING_PATTERNS.get(policy_rule_id, [])
    if not patterns:
        return 0

    conditions = [Finding.rule_id.ilike(f"%{p}%") for p in patterns]
    # OR all conditions together
    combined = conditions[0]
    for cond in conditions[1:]:
        combined = combined | cond

    stmt = select(func.count()).select_from(Finding).where(combined)
    result = await session.execute(stmt)
    return result.scalar_one()


@router.get("/rules", response_model=PolicyRuleListResponse)
async def list_policy_rules(
    session: AsyncSession = Depends(get_session),
) -> PolicyRuleListResponse:
    """List all policy rules with violation counts from the findings table."""
    rules: list[PolicyRule] = []
    for rule_def in _DEFAULT_RULES:
        rule_id = rule_def["id"]
        violation_count = await _count_violations_for_rule(session, rule_id)
        rules.append(
            PolicyRule(
                id=rule_id,
                name=rule_def["name"],
                description=rule_def["description"],
                severity=rule_def["severity"],
                enabled=_rule_enabled_state.get(rule_id, True),
                violation_count=violation_count,
            )
        )

    return PolicyRuleListResponse(rules=rules, total=len(rules))


@router.put("/rules/{rule_id}", response_model=PolicyRule)
async def toggle_policy_rule(
    rule_id: str,
    body: PolicyRuleToggle,
    session: AsyncSession = Depends(get_session),
) -> PolicyRule:
    """Toggle enable/disable for a policy rule."""
    # Validate rule_id exists
    rule_def = next((r for r in _DEFAULT_RULES if r["id"] == rule_id), None)
    if rule_def is None:
        raise HTTPException(status_code=404, detail=f"Policy rule '{rule_id}' not found")

    _rule_enabled_state[rule_id] = body.enabled

    violation_count = await _count_violations_for_rule(session, rule_id)

    return PolicyRule(
        id=rule_id,
        name=rule_def["name"],
        description=rule_def["description"],
        severity=rule_def["severity"],
        enabled=body.enabled,
        violation_count=violation_count,
    )
