"""Comprehensive database seed script for CipherRadar development.

Usage:
    python scripts/seed.py

Populates the database with realistic test data: users, groups, projects,
scans, findings, CBOM documents, and notifications.

Connects to the database using asyncpg (raw SQL) for speed.
Idempotent: checks for existing seed data and skips if found.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import uuid
from datetime import UTC, datetime, timedelta

import asyncpg
import bcrypt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "SEED_DATABASE_URL",
    os.environ.get(
        "CBOM_DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5433/cipherradar",
    ),
)


def _to_dsn(url: str) -> str:
    """Convert SQLAlchemy async URL to a plain DSN for asyncpg."""
    return url.replace("postgresql+asyncpg://", "postgresql://")


DSN = _to_dsn(DATABASE_URL)

# ---------------------------------------------------------------------------
# Deterministic UUIDs (so seed is idempotent / reproducible)
# ---------------------------------------------------------------------------


def _duuid(name: str) -> uuid.UUID:
    """Generate a deterministic UUID v5 from a seed name."""
    return uuid.uuid5(uuid.NAMESPACE_DNS, f"cipherradar.seed.{name}")


# Org
ORG_ID = _duuid("org.default")

# Groups
GRP_ROOT = _duuid("group.default-org")
GRP_ENGINEERING = _duuid("group.engineering")
GRP_BACKEND = _duuid("group.backend-team")
GRP_FRONTEND = _duuid("group.frontend-team")
GRP_SECURITY = _duuid("group.security")

# Users
USR_ADMIN = _duuid("user.admin")
USR_SEC_MGR = _duuid("user.security-mgr")
USR_SEC_ENG = _duuid("user.security-eng")
USR_TEAM_LEAD = _duuid("user.team-lead")
USR_AUDITOR = _duuid("user.auditor")
USR_DEVELOPER = _duuid("user.developer")
USR_VIEWER = _duuid("user.viewer")

# Projects
PRJ_PAYMENT = _duuid("project.payment-service")
PRJ_AUTH = _duuid("project.auth-api")
PRJ_PIPELINE = _duuid("project.data-pipeline")
PRJ_MOBILE = _duuid("project.mobile-backend")
PRJ_WEBFRONT = _duuid("project.web-frontend")
PRJ_INFRA = _duuid("project.infra-tools")


NOW = datetime.now(UTC)


# ---------------------------------------------------------------------------
# Helper data
# ---------------------------------------------------------------------------

USERS = [
    (USR_ADMIN, "admin@cipherradar.local", "admin123", "org_admin"),
    (USR_SEC_MGR, "security-mgr@cipherradar.local", "password123", "security_manager"),
    (USR_SEC_ENG, "security-eng@cipherradar.local", "password123", "security_engineer"),
    (USR_TEAM_LEAD, "team-lead@cipherradar.local", "password123", "team_manager"),
    (USR_AUDITOR, "auditor@cipherradar.local", "password123", "compliance_auditor"),
    (USR_DEVELOPER, "developer@cipherradar.local", "password123", "developer"),
    (USR_VIEWER, "viewer@cipherradar.local", "password123", "guest"),
]

GROUPS = [
    (GRP_ROOT, None, "Default Org"),
    (GRP_ENGINEERING, GRP_ROOT, "Engineering"),
    (GRP_BACKEND, GRP_ENGINEERING, "Backend Team"),
    (GRP_FRONTEND, GRP_ENGINEERING, "Frontend Team"),
    (GRP_SECURITY, GRP_ROOT, "Security"),
]

PROJECTS = [
    (PRJ_PAYMENT, GRP_BACKEND, "payment-service", "https://github.com/nk-sentinel/payment-service", "github"),
    (PRJ_AUTH, GRP_BACKEND, "auth-api", "https://github.com/nk-sentinel/auth-api", "github"),
    (PRJ_PIPELINE, GRP_BACKEND, "data-pipeline", "https://gitlab.com/nk-sentinel/data-pipeline", "gitlab"),
    (PRJ_MOBILE, GRP_FRONTEND, "mobile-backend", "https://bitbucket.org/nk-sentinel/mobile-backend", "bitbucket"),
    (PRJ_WEBFRONT, GRP_FRONTEND, "web-frontend", "https://github.com/nk-sentinel/web-frontend", "github"),
    (PRJ_INFRA, GRP_SECURITY, "infra-tools", "https://github.com/nk-sentinel/infra-tools", "github"),
]

PROJECT_LANGUAGES = {
    PRJ_PAYMENT: ["Java", "Python"],
    PRJ_AUTH: ["Python", "JavaScript"],
    PRJ_PIPELINE: ["Python"],
    PRJ_MOBILE: ["Java", "Kotlin"],
    PRJ_WEBFRONT: ["JavaScript", "TypeScript"],
    PRJ_INFRA: ["Go"],
}

# ---------------------------------------------------------------------------
# Finding templates — realistic crypto findings
# ---------------------------------------------------------------------------

FINDING_TEMPLATES = [
    # CRITICAL
    {
        "rule_id": "cbom-python-ssl-no-verify",
        "name": "SSL certificate verification disabled (CERT_NONE)",
        "severity": "critical",
        "confidence": "high",
        "quantum_status": "not_applicable",
        "asset_type": "protocol",
        "files": {"Python": ["src/client.py", "lib/http_client.py", "utils/api.py"]},
        "properties": {"algorithm": "TLS", "issue": "ssl.CERT_NONE", "recommendation": "Use ssl.CERT_REQUIRED"},
    },
    {
        "rule_id": "cbom-python-jwt-alg-none",
        "name": "JWT accepts algorithm 'none' — signature bypass",
        "severity": "critical",
        "confidence": "high",
        "quantum_status": "not_applicable",
        "asset_type": "protocol",
        "files": {"Python": ["auth/jwt_handler.py", "middleware/auth.py"], "JavaScript": ["src/auth/jwt.js"]},
        "properties": {"algorithm": "JWT", "issue": "alg:none accepted", "recommendation": "Restrict to RS256/ES256"},
    },
    # HIGH
    {
        "rule_id": "cbom-java-md5-usage",
        "name": "MD5 hash function used — collision-prone",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "broken",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/util/HashUtil.java", "src/main/java/com/app/crypto/Legacy.java"],
                  "Python": ["utils/hash.py", "legacy/digest.py"]},
        "properties": {"algorithm": "MD5", "key_size": None, "recommendation": "Migrate to SHA-256 or SHA-3"},
    },
    {
        "rule_id": "cbom-java-sha1-usage",
        "name": "SHA-1 hash function used — deprecated",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "broken",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/sign/Signer.java"],
                  "Python": ["crypto/signing.py"],
                  "JavaScript": ["src/utils/hash.js"]},
        "properties": {"algorithm": "SHA-1", "recommendation": "Migrate to SHA-256 or SHA-3"},
    },
    {
        "rule_id": "cbom-java-des-usage",
        "name": "DES encryption used — insecure block cipher",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "broken",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/crypto/DESCipher.java"],
                  "Kotlin": ["src/main/kotlin/crypto/LegacyEncrypt.kt"]},
        "properties": {"algorithm": "DES", "key_size": 56, "recommendation": "Migrate to AES-256-GCM"},
    },
    {
        "rule_id": "cbom-java-3des-usage",
        "name": "3DES encryption used — deprecated cipher",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "vulnerable",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/crypto/TripleDES.java"],
                  "Python": ["crypto/triple_des.py"]},
        "properties": {"algorithm": "3DES", "key_size": 168, "recommendation": "Migrate to AES-256-GCM"},
    },
    {
        "rule_id": "cbom-python-rc4-usage",
        "name": "RC4 stream cipher used — known broken",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "broken",
        "asset_type": "algorithm",
        "files": {"Python": ["legacy/stream.py"], "Java": ["src/main/java/com/app/crypto/RC4Cipher.java"]},
        "properties": {"algorithm": "RC4", "recommendation": "Migrate to ChaCha20-Poly1305 or AES-GCM"},
    },
    {
        "rule_id": "cbom-python-tls10-usage",
        "name": "TLS 1.0 protocol — deprecated and insecure",
        "severity": "high",
        "confidence": "high",
        "quantum_status": "not_applicable",
        "asset_type": "protocol",
        "files": {"Python": ["config/tls.py", "network/ssl_config.py"],
                  "JavaScript": ["src/config/https.js"]},
        "properties": {"algorithm": "TLS 1.0", "recommendation": "Enforce TLS 1.2 or TLS 1.3 minimum"},
    },
    {
        "rule_id": "cbom-java-hardcoded-key",
        "name": "Hardcoded cryptographic key material detected",
        "severity": "high",
        "confidence": "medium",
        "quantum_status": "not_applicable",
        "asset_type": "key",
        "files": {"Java": ["src/main/java/com/app/config/Secrets.java"],
                  "Python": ["config/secrets.py", "settings.py"],
                  "JavaScript": ["src/config/keys.js"],
                  "Go": ["internal/config/keys.go"]},
        "properties": {"algorithm": "AES-256", "issue": "hardcoded key", "recommendation": "Use KMS or vault"},
    },
    # MEDIUM
    {
        "rule_id": "cbom-java-rsa2048-quantum",
        "name": "RSA-2048 — quantum vulnerable",
        "severity": "medium",
        "confidence": "high",
        "quantum_status": "vulnerable",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/crypto/RSAKeyGen.java", "src/main/java/com/app/sign/RSASigner.java"],
                  "Python": ["crypto/rsa_utils.py"],
                  "Go": ["internal/crypto/rsa.go"],
                  "Kotlin": ["src/main/kotlin/crypto/RSAHelper.kt"]},
        "properties": {"algorithm": "RSA", "key_size": 2048, "quantum_risk": "Shor's algorithm", "recommendation": "Plan migration to ML-KEM-768 (CRYSTALS-Kyber)"},
    },
    {
        "rule_id": "cbom-python-ecdsa-p256-quantum",
        "name": "ECDSA P-256 — quantum vulnerable",
        "severity": "medium",
        "confidence": "high",
        "quantum_status": "vulnerable",
        "asset_type": "algorithm",
        "files": {"Python": ["crypto/ecdsa_sign.py"],
                  "Java": ["src/main/java/com/app/sign/ECDSASigner.java"],
                  "Go": ["internal/crypto/ecdsa.go"]},
        "properties": {"algorithm": "ECDSA-P256", "key_size": 256, "quantum_risk": "Shor's algorithm", "recommendation": "Plan migration to ML-DSA (CRYSTALS-Dilithium)"},
    },
    {
        "rule_id": "cbom-python-pbkdf2-low-iterations",
        "name": "PBKDF2 with insufficient iterations (<100,000)",
        "severity": "medium",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "files": {"Python": ["auth/password.py", "utils/kdf.py"],
                  "Java": ["src/main/java/com/app/auth/PasswordHasher.java"],
                  "JavaScript": ["src/auth/pbkdf2.js"]},
        "properties": {"algorithm": "PBKDF2-HMAC-SHA256", "iterations": 10000, "recommendation": "Increase to >= 600,000 iterations or use Argon2id"},
    },
    {
        "rule_id": "cbom-java-dh2048-quantum",
        "name": "Diffie-Hellman 2048-bit — quantum vulnerable",
        "severity": "medium",
        "confidence": "high",
        "quantum_status": "vulnerable",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/crypto/DHKeyExchange.java"],
                  "Python": ["crypto/dh.py"]},
        "properties": {"algorithm": "DH", "key_size": 2048, "quantum_risk": "Shor's algorithm", "recommendation": "Migrate to ML-KEM-768"},
    },
    # LOW
    {
        "rule_id": "cbom-java-aes256gcm-safe",
        "name": "AES-256-GCM detected — quantum safe",
        "severity": "low",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/crypto/AESGCMCipher.java", "src/main/java/com/app/service/EncryptionService.java"],
                  "Python": ["crypto/aes_gcm.py", "services/encrypt.py"],
                  "Go": ["internal/crypto/aes.go"],
                  "Kotlin": ["src/main/kotlin/crypto/AESEncrypt.kt"],
                  "JavaScript": ["src/crypto/aes.js"],
                  "TypeScript": ["src/crypto/aes-gcm.ts"]},
        "properties": {"algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM", "status": "Grover's algorithm doubles effective search, 128-bit security remains adequate"},
    },
    {
        "rule_id": "cbom-python-sha256-safe",
        "name": "SHA-256 hash function — quantum safe",
        "severity": "info",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "files": {"Python": ["utils/hash.py", "crypto/integrity.py"],
                  "Java": ["src/main/java/com/app/util/DigestUtil.java"],
                  "Go": ["internal/crypto/hash.go"],
                  "JavaScript": ["src/utils/sha256.js"]},
        "properties": {"algorithm": "SHA-256", "status": "Grover's attack reduces to 128-bit security — still adequate"},
    },
    {
        "rule_id": "cbom-go-chacha20-safe",
        "name": "ChaCha20-Poly1305 AEAD — quantum safe",
        "severity": "info",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "files": {"Go": ["internal/crypto/chacha.go"],
                  "Python": ["crypto/chacha.py"],
                  "JavaScript": ["src/crypto/chacha20.js"]},
        "properties": {"algorithm": "ChaCha20-Poly1305", "key_size": 256, "status": "Symmetric — quantum resistant"},
    },
    {
        "rule_id": "cbom-python-hkdf-safe",
        "name": "HKDF key derivation — quantum safe",
        "severity": "info",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "files": {"Python": ["crypto/kdf.py"], "Java": ["src/main/java/com/app/crypto/HKDFDeriver.java"],
                  "Go": ["internal/crypto/hkdf.go"]},
        "properties": {"algorithm": "HKDF-SHA256", "status": "Symmetric KDF — quantum resistant"},
    },
    {
        "rule_id": "cbom-java-hmac-sha256",
        "name": "HMAC-SHA256 message authentication — quantum safe",
        "severity": "info",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "files": {"Java": ["src/main/java/com/app/auth/HMACVerifier.java"],
                  "Python": ["auth/hmac_verify.py"],
                  "JavaScript": ["src/auth/hmac.js"]},
        "properties": {"algorithm": "HMAC-SHA256", "key_size": 256, "status": "Symmetric — quantum resistant"},
    },
    {
        "rule_id": "cbom-java-tls13-safe",
        "name": "TLS 1.3 protocol in use — current best practice",
        "severity": "info",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "protocol",
        "files": {"Java": ["src/main/java/com/app/config/TLSConfig.java"],
                  "Python": ["config/tls.py"],
                  "Go": ["internal/server/tls.go"]},
        "properties": {"algorithm": "TLS 1.3", "status": "Current recommended protocol"},
    },
]


def _sha(text: str) -> str:
    """Generate a fake commit SHA from a string."""
    return hashlib.sha1(text.encode()).hexdigest()[:40]


def _gen_findings_for_scan(
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    scan_index: int,
    org_id: uuid.UUID,
) -> list[dict]:
    """Generate 15-30 realistic findings for a given scan."""
    langs = PROJECT_LANGUAGES.get(project_id, ["Python"])
    rng = random.Random(f"{project_id}-{scan_index}")
    count = rng.randint(15, 30)
    findings = []

    for i in range(count):
        template = rng.choice(FINDING_TEMPLATES)
        # Pick a file that matches one of the project's languages
        matching_files = []
        for lang in langs:
            if lang in template["files"]:
                for f in template["files"][lang]:
                    matching_files.append(f)
        if not matching_files:
            # Fall back to first available language
            first_lang = next(iter(template["files"]))
            matching_files = template["files"][first_lang]

        chosen_file = rng.choice(matching_files)
        line = rng.randint(10, 500)

        finding_id = _duuid(f"finding.{scan_id}.{i}")
        findings.append({
            "id": finding_id,
            "scan_id": scan_id,
            "project_id": project_id,
            "org_id": org_id,
            "rule_id": template["rule_id"],
            "name": template["name"],
            "severity": template["severity"],
            "confidence": template["confidence"],
            "quantum_status": template["quantum_status"],
            "asset_type": template["asset_type"],
            "location_file": chosen_file,
            "location_line": line,
            "properties": json.dumps(template["properties"]),
        })

    return findings


def _gen_cbom_document(scan_id: uuid.UUID, findings: list[dict]) -> dict:
    """Generate a minimal CycloneDX 1.7 CBOM JSON for a scan."""
    components = []
    seen = set()
    for f in findings:
        props = json.loads(f["properties"]) if isinstance(f["properties"], str) else f["properties"]
        algo = props.get("algorithm", f["name"])
        if algo not in seen:
            seen.add(algo)
            components.append({
                "type": "crypto-asset",
                "name": algo,
                "cryptoProperties": {
                    "assetType": f["asset_type"],
                    "algorithmProperties": {
                        "parameterSetIdentifier": str(props.get("key_size", "")),
                    },
                },
            })

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": components,
    }
    return cbom


# ---------------------------------------------------------------------------
# Notification data
# ---------------------------------------------------------------------------

NOTIFICATION_TEMPLATES = [
    {
        "trigger_type": "scan_completed",
        "severity": "info",
        "title": "Scan completed for payment-service",
        "message": "Scan #47 on branch main completed with 342 findings (5 critical).",
        "link": f"/repos/{PRJ_PAYMENT}/scans",
        "read": False,
    },
    {
        "trigger_type": "critical_finding",
        "severity": "critical",
        "title": "Critical: SSL verification disabled in auth-api",
        "message": "A new critical finding was detected: SSL CERT_NONE in src/client.py:42.",
        "link": f"/repos/{PRJ_AUTH}/findings",
        "read": False,
    },
    {
        "trigger_type": "scan_violations",
        "severity": "high",
        "title": "3 new compliance violations in mobile-backend",
        "message": "Scan #15 introduced 3 new NIST 800-131A violations: DES, RC4, MD5.",
        "link": f"/repos/{PRJ_MOBILE}/compliance",
        "read": False,
    },
    {
        "trigger_type": "cert_expiry_30d",
        "severity": "medium",
        "title": "Certificate expiring in 28 days",
        "message": "The TLS certificate for api.payment-service.internal expires on 2026-04-18.",
        "link": "/certificates",
        "read": False,
    },
    {
        "trigger_type": "scan_completed",
        "severity": "info",
        "title": "Scan completed for data-pipeline",
        "message": "Scan #22 on branch main completed with 98 findings (0 critical). All clean!",
        "link": f"/repos/{PRJ_PIPELINE}/scans",
        "read": True,
    },
    {
        "trigger_type": "suppression_submitted",
        "severity": "info",
        "title": "Suppression request submitted",
        "message": "Developer developer@cipherradar.local submitted a suppression for cbom-java-md5-usage in payment-service.",
        "link": f"/repos/{PRJ_PAYMENT}/findings",
        "read": True,
    },
    {
        "trigger_type": "critical_finding",
        "severity": "critical",
        "title": "Critical: JWT algorithm 'none' in auth-api",
        "message": "JWT alg:none vulnerability detected in auth/jwt_handler.py:18. Immediate remediation required.",
        "link": f"/repos/{PRJ_AUTH}/findings",
        "read": False,
    },
    {
        "trigger_type": "scan_completed",
        "severity": "info",
        "title": "Scan completed for web-frontend",
        "message": "Scan #8 on branch main completed with 124 findings (1 critical).",
        "link": f"/repos/{PRJ_WEBFRONT}/scans",
        "read": True,
    },
    {
        "trigger_type": "scan_violations",
        "severity": "high",
        "title": "New hardcoded key in infra-tools",
        "message": "Scan #5 detected a hardcoded AES key in internal/config/keys.go:34.",
        "link": f"/repos/{PRJ_INFRA}/findings",
        "read": False,
    },
    {
        "trigger_type": "cert_expiry_30d",
        "severity": "medium",
        "title": "Certificate expiring in 14 days",
        "message": "The code-signing certificate for mobile-backend expires on 2026-04-04.",
        "link": "/certificates",
        "read": True,
    },
]


# ---------------------------------------------------------------------------
# Seed logic
# ---------------------------------------------------------------------------


async def seed_database() -> None:
    """Seed the database with development data."""
    conn: asyncpg.Connection = await asyncpg.connect(DSN)
    try:
        # Idempotency check: skip if projects already seeded
        row = await conn.fetchval("SELECT COUNT(*) FROM projects")
        if row and row > 0:
            print("[seed] Projects already exist — skipping seed.")
            await conn.close()
            return

        print("[seed] Starting database seed...")

        # ------------------------------------------------------------------
        # 1. Organisation
        # ------------------------------------------------------------------
        existing_org = await conn.fetchval(
            "SELECT id FROM organisations WHERE name = 'Default'",
        )
        if existing_org:
            org_id = existing_org
            print(f"[seed] Organisation 'Default' already exists: {org_id}")
        else:
            org_id = ORG_ID
            await conn.execute(
                """INSERT INTO organisations (id, name, plan, description, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $5)""",
                org_id, "Default", "enterprise", "Default development organisation", NOW,
            )
            print(f"[seed] Created organisation 'Default': {org_id}")

        # ------------------------------------------------------------------
        # 2. Users
        # ------------------------------------------------------------------
        user_count = 0
        for uid, email, password, role in USERS:
            exists = await conn.fetchval(
                "SELECT id FROM users WHERE email = $1", email,
            )
            if exists:
                continue
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            await conn.execute(
                """INSERT INTO users (id, email, hashed_password, role, is_active, org_id, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, true, $5, $6, $6)""",
                uid, email, hashed, role, org_id, NOW,
            )
            user_count += 1

        print(f"[seed] Users created: {user_count} (skipped existing)")

        # ------------------------------------------------------------------
        # 3. Groups (hierarchical)
        # ------------------------------------------------------------------
        group_count = 0
        for gid, parent_id, name in GROUPS:
            exists = await conn.fetchval("SELECT id FROM groups WHERE id = $1", gid)
            if exists:
                continue
            await conn.execute(
                """INSERT INTO groups (id, org_id, parent_group_id, name, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $5)""",
                gid, org_id, parent_id, name, NOW,
            )
            group_count += 1

        print(f"[seed] Groups created: {group_count}")

        # ------------------------------------------------------------------
        # 4. Projects
        # ------------------------------------------------------------------
        project_count = 0
        for pid, gid, name, git_url, provider in PROJECTS:
            settings_json = json.dumps({"languages": PROJECT_LANGUAGES.get(pid, [])})
            await conn.execute(
                """INSERT INTO projects (id, group_id, org_id, name, git_url, provider, settings, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)""",
                pid, gid, org_id, name, git_url, provider, settings_json, NOW,
            )
            project_count += 1

        print(f"[seed] Projects created: {project_count}")

        # ------------------------------------------------------------------
        # 5. Scans (3 per project = 18)
        # ------------------------------------------------------------------
        scan_count = 0
        finding_count = 0
        cbom_count = 0

        all_scans = []  # (scan_id, project_id, scan_index)

        for pid, _gid, _pname, _url, _prov in PROJECTS:
            for scan_idx in range(3):
                scan_id = _duuid(f"scan.{pid}.{scan_idx}")
                days_ago = 30 - (scan_idx * 10) + random.randint(-2, 2)
                started = NOW - timedelta(days=max(1, days_ago), hours=random.randint(0, 12))
                completed = started + timedelta(seconds=random.randint(2, 8))
                commit = _sha(f"{pid}-{scan_idx}-commit")
                branch = "main" if scan_idx < 2 else random.choice(["main", "develop", "feat/auth", "fix/crypto"])

                all_scans.append((scan_id, pid, scan_idx, started, completed, commit, branch))

        # Insert scans first
        for scan_id, pid, _scan_idx, started, completed, commit, branch in all_scans:
            await conn.execute(
                """INSERT INTO scans (id, project_id, org_id, status, branch, commit_sha,
                                      started_at, completed_at, findings_count, created_at, updated_at)
                   VALUES ($1, $2, $3, 'completed', $4, $5, $6, $7, 0, $6, $7)""",
                scan_id, pid, org_id, branch, commit, started, completed,
            )
            scan_count += 1

        # Insert findings for each scan
        for scan_id, pid, scan_idx, started, _completed, _commit, _branch in all_scans:
            findings = _gen_findings_for_scan(pid, scan_id, scan_idx, org_id)

            for f in findings:
                await conn.execute(
                    """INSERT INTO findings (id, scan_id, project_id, org_id, rule_id, name,
                                            severity, confidence, quantum_status, asset_type,
                                            location_file, location_line, properties, created_at, updated_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)""",
                    f["id"], f["scan_id"], f["project_id"], f["org_id"],
                    f["rule_id"], f["name"], f["severity"], f["confidence"],
                    f["quantum_status"], f["asset_type"],
                    f["location_file"], f["location_line"],
                    f["properties"],
                    started,
                )
                finding_count += 1

            # Update findings_count on scan
            await conn.execute(
                "UPDATE scans SET findings_count = $1 WHERE id = $2",
                len(findings), scan_id,
            )

            # CBOM document
            cbom_id = _duuid(f"cbom.{scan_id}")
            cbom_json = _gen_cbom_document(scan_id, findings)
            await conn.execute(
                """INSERT INTO cbom_documents (id, scan_id, org_id, storage_uri, spec_version,
                                               serial_number, cbom_json, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)""",
                cbom_id, scan_id, org_id,
                f"postgres://{cbom_id}",
                "1.7",
                cbom_json["serialNumber"],
                json.dumps(cbom_json),
                started,
            )
            cbom_count += 1

        print(f"[seed] Scans created: {scan_count}")
        print(f"[seed] Findings created: {finding_count}")
        print(f"[seed] CBOM documents created: {cbom_count}")

        # ------------------------------------------------------------------
        # 6. Notifications (10 for admin user)
        # ------------------------------------------------------------------
        notif_count = 0
        admin_user_id = await conn.fetchval(
            "SELECT id FROM users WHERE email = 'admin@cipherradar.local'",
        )
        if admin_user_id:
            for idx, tmpl in enumerate(NOTIFICATION_TEMPLATES):
                notif_id = _duuid(f"notification.{idx}")
                created = NOW - timedelta(hours=idx * 3, minutes=random.randint(0, 59))
                await conn.execute(
                    """INSERT INTO notifications (id, user_id, org_id, trigger_type, severity,
                                                   title, message, link, read, created_at, updated_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)""",
                    notif_id, admin_user_id, org_id,
                    tmpl["trigger_type"], tmpl["severity"],
                    tmpl["title"], tmpl["message"], tmpl["link"],
                    tmpl["read"], created,
                )
                notif_count += 1

        print(f"[seed] Notifications created: {notif_count}")

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        print()
        print("=" * 50)
        print("  SEED COMPLETE")
        print("=" * 50)
        print("  Organisation:     1")
        print(f"  Users:            {user_count} new")
        print(f"  Groups:           {group_count}")
        print(f"  Projects:         {project_count}")
        print(f"  Scans:            {scan_count}")
        print(f"  Findings:         {finding_count}")
        print(f"  CBOM Documents:   {cbom_count}")
        print(f"  Notifications:    {notif_count}")
        print("=" * 50)

    except Exception as e:
        print(f"[seed] ERROR: {e}")
        raise
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(seed_database())
