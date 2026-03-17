# Data Model

> **Document version:** v1
> **Created:** 2026-03-15
> **Last updated:** 2026-03-15
> **Status:** Active

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-15 | Initial document | — |

---

## 1. Core Entities

```
Organisation
  └── Projects  (repositories / services)
        └── Scans  (timestamped runs)
              └── CBOM Documents  (CycloneDX 1.7 — immutable per scan)
                    └── Components
                          ├── Algorithm assets
                          │     └── cryptoProperties.algorithmProperties
                          ├── Protocol assets
                          │     └── cryptoProperties.protocolProperties
                          ├── Certificate assets
                          │     └── cryptoProperties.certificateProperties
                          └── RelatedCryptoMaterial assets
                                └── cryptoProperties.relatedCryptoMaterialProperties

PolicySets
  └── Rules ──────────────────────────▶ evaluate against CBOM Components
                                              └── PolicyViolations

ComplianceFrameworks
  └── Requirements ──────────────────▶ map to PolicyViolations / CBOM Components

Findings  (= PolicyViolations enriched with location + remediation)
  ├── file_path, line_number, column, code_snippet
  ├── severity  (Critical / High / Medium / Low / Info)
  ├── confidence  (High / Medium / Low / Unresolved)
  ├── cwe_id, owasp_ref
  ├── quantum_status  (vulnerable / safe / unknown / broken)
  ├── compliance_statuses  [ { framework, status, requirement } ]
  └── remediation_guidance
```

---

## 2. CycloneDX 1.7 CBOM Schema

### 2.1 Algorithm Component

```json
{
  "type": "cryptoAsset",
  "bom-ref": "algo-aes-256-gcm-1",
  "name": "AES",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "ae",
      "parameterSetIdentifier": "256",
      "mode": "gcm",
      "padding": "none",
      "executionEnvironment": "softwarePlainRam",
      "implementationPlatform": "x86-64",
      "certificationLevel": ["fips140-3"],
      "cryptoFunctions": ["encrypt", "decrypt"],
      "classicalSecurityLevel": 256,
      "nistQuantumSecurityLevel": 5
    },
    "oid": "2.16.840.1.101.3.4.1.46"
  },
  "evidence": {
    "occurrences": [
      {
        "location": "src/crypto/EncryptionService.java",
        "line": 142,
        "column": 18,
        "symbol": "Cipher.getInstance"
      }
    ]
  }
}
```

### 2.2 Protocol Component

```json
{
  "type": "cryptoAsset",
  "bom-ref": "proto-tls13-1",
  "name": "TLS",
  "cryptoProperties": {
    "assetType": "protocol",
    "protocolProperties": {
      "type": "tls",
      "version": "1.3",
      "cipherSuites": [
        {
          "name": "TLS_AES_256_GCM_SHA384",
          "identifiers": ["0x1302"],
          "algorithms": ["algo-aes-256-gcm-1", "algo-sha384-1"]
        },
        {
          "name": "TLS_CHACHA20_POLY1305_SHA256",
          "identifiers": ["0x1303"],
          "algorithms": ["algo-chacha20-poly1305-1", "algo-sha256-1"]
        }
      ]
    }
  }
}
```

### 2.3 Certificate Component

```json
{
  "type": "cryptoAsset",
  "bom-ref": "cert-tls-prod-1",
  "name": "api.example.com TLS Certificate",
  "cryptoProperties": {
    "assetType": "certificate",
    "certificateProperties": {
      "subjectName": "CN=api.example.com, O=Example Corp, C=US",
      "issuerName": "CN=Let's Encrypt R3, O=Let's Encrypt, C=US",
      "notValidBefore": "2025-01-01T00:00:00Z",
      "notValidAfter": "2025-04-01T00:00:00Z",
      "certificateAlgorithm": "SHA256withECDSA",
      "certificateFormat": "X.509"
    }
  }
}
```

### 2.4 Related Crypto Material Component

```json
{
  "type": "cryptoAsset",
  "bom-ref": "material-rsa-private-key-1",
  "name": "RSA Private Key",
  "cryptoProperties": {
    "assetType": "relatedCryptoMaterial",
    "relatedCryptoMaterialProperties": {
      "type": "privateKey",
      "size": 2048,
      "format": "PEM",
      "algorithmRef": "algo-rsa-2048-1",
      "state": "active",
      "activationDate": "2024-01-01T00:00:00Z",
      "expirationDate": "2026-01-01T00:00:00Z"
    }
  }
}
```

### 2.5 Hardcoded IV (Misuse Example)

```json
{
  "type": "cryptoAsset",
  "bom-ref": "material-static-iv-1",
  "name": "Static Initialization Vector",
  "cryptoProperties": {
    "assetType": "relatedCryptoMaterial",
    "relatedCryptoMaterialProperties": {
      "type": "initializationVector",
      "size": 128,
      "format": "raw",
      "algorithmRef": "algo-aes-128-cbc-1",
      "state": "active"
    }
  },
  "CipherRadar": {
    "isDynamic": false,
    "misuse": "STATIC_IV",
    "severity": "CRITICAL",
    "cwe": "CWE-329",
    "confidence": "high",
    "location": "src/legacy/Encryptor.java:87"
  }
}
```

---

## 3. Dependency Modelling

CycloneDX dependency arrays model relationships between crypto components:

```json
{
  "dependencies": [
    {
      "ref": "service-payment-api",
      "dependsOn": ["proto-tls13-1", "algo-aes-256-gcm-1"]
    },
    {
      "ref": "proto-tls13-1",
      "dependsOn": ["algo-aes-256-gcm-1", "algo-ecdhe-p256-1", "algo-sha384-1"]
    },
    {
      "ref": "algo-aes-256-gcm-1",
      "dependsOn": ["material-aes-256-key-1"]
    }
  ]
}
```

This enables queries like:
- "Which services use TLS 1.2 or below?"
- "Which services have any quantum-vulnerable key exchange?"
- "Which algorithms are used by more than 10 services?" (migration blast radius)

---

## 4. Scan Record Schema

```json
{
  "scanId": "scan-2026-03-15-abc123",
  "projectId": "proj-payment-service",
  "repository": "https://github.com/example/payment-service",
  "branch": "main",
  "commitSha": "a1b2c3d4e5f6...",
  "scannerVersion": "1.2.0",
  "startedAt": "2026-03-15T10:00:00Z",
  "completedAt": "2026-03-15T10:03:42Z",
  "durationSeconds": 222,
  "filesScanned": 847,
  "linesScanned": 124391,
  "findingsTotal": 23,
  "findingsBySeverity": {
    "critical": 2,
    "high": 8,
    "medium": 9,
    "low": 4
  },
  "policyResult": "FAIL",
  "policyViolations": 2,
  "cbomDocumentRef": "cbom-2026-03-15-abc123.json",
  "cbomDocumentSha256": "e3b0c44298fc1c149afb..."
}
```

---

## 5. CBOM Diff Schema

When comparing two scans, the diff output follows this structure:

```json
{
  "diffId": "diff-abc123-def456",
  "baseScanId": "scan-2026-03-01-abc123",
  "headScanId": "scan-2026-03-15-def456",
  "summary": {
    "added": 3,
    "removed": 1,
    "changed": 2,
    "unchanged": 17
  },
  "changes": [
    {
      "type": "ADDED",
      "component": { ... },
      "severity": "HIGH",
      "description": "New usage of RSA-1024 detected in src/auth/LegacyAuth.java:44"
    },
    {
      "type": "REMOVED",
      "component": { ... },
      "description": "MD5 usage removed from src/util/HashUtils.java"
    },
    {
      "type": "CHANGED",
      "field": "algorithmProperties.mode",
      "from": "cbc",
      "to": "gcm",
      "description": "AES mode upgraded from CBC to GCM in src/crypto/FileEncryptor.java:31"
    }
  ]
}
```
