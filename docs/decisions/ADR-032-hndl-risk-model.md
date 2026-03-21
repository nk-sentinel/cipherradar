# ADR-032: HNDL Risk Model — Mosca Inequality + Multiplicative Score

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

"Harvest Now, Decrypt Later" (HNDL) is the primary threat model driving post-quantum cryptography migration urgency. Nation-state adversaries are harvesting encrypted traffic today with the expectation that future quantum computers will be able to decrypt it. The risk is real for any data whose confidentiality must last beyond the expected arrival of cryptographically relevant quantum computers (CRQC).

Security teams need a per-finding and per-project risk score that quantifies HNDL exposure based on three dimensions: how sensitive the protected data is, how vulnerable the algorithm is to quantum attack, and how much time remains before quantum computing makes the algorithm breakable.

Michele Mosca's inequality (2015) provides the theoretical framework: if `shelf_life + migration_time > quantum_timeline`, migration is already overdue.

---

## Decision

### Multiplicative risk score

```
HNDL_risk = data_sensitivity × quantum_vulnerability × time_factor
```

Each factor is a normalised value between 0.0 and 1.0. The multiplicative model ensures that a zero in any factor zeros the entire risk — quantum-safe algorithms have zero risk regardless of data sensitivity, and public data has negligible risk regardless of algorithm.

### Factor 1: Data Sensitivity

Classified per-finding based on the context where the cryptographic operation is used. Default classification can be overridden via policy rules in `.cradar.yml`.

| Classification | Value | Examples |
|---|---|---|
| Public | 0.1 | Public API responses, open-source checksums |
| Internal | 0.4 | Internal service-to-service communication, logs |
| Confidential | 0.7 | Customer PII, financial transactions, health records |
| Restricted | 1.0 | Classified data, trade secrets, long-term key material |

**Default:** If no classification is configured, findings default to `Internal (0.4)` — a conservative-but-not-alarmist baseline.

### Factor 2: Quantum Vulnerability

Derived from the quantum algorithm table in `scanner/library-models/` (embedded per ADR-010).

| Status | Value | Algorithms |
|---|---|---|
| Quantum-safe | 0.0 | ML-KEM, ML-DSA, SLH-DSA, XMSS, AES-256, SHA-3 |
| Hybrid | 0.2 | X25519+ML-KEM composite, RSA+ML-KEM hybrid |
| Unknown | 0.5 | Custom or unrecognised algorithms |
| Quantum-vulnerable | 1.0 | RSA, ECDSA, ECDH, DH, DSA, all <256-bit symmetric |

### Factor 3: Time Factor

Measures urgency based on proximity to the estimated quantum deadline.

```
time_factor = max(0, 1 - (quantum_deadline - current_year) / 15)
```

| Parameter | Default | Configurable |
|---|---|---|
| `quantum_deadline` | 2035 | Yes, via `CRADAR_QUANTUM_DEADLINE` or `.cradar.yml` |
| Denominator (15) | Fixed | Represents the planning horizon in years |

**Behaviour:**
- If `current_year >= quantum_deadline`: `time_factor = 1.0` (maximum urgency)
- At 15 years before deadline: `time_factor = 0.0` (no time pressure)
- Linear interpolation between: closer to deadline = higher urgency

**Example (current year 2026, deadline 2035):**
`time_factor = max(0, 1 - (2035 - 2026) / 15) = max(0, 1 - 0.6) = 0.4`

### Mosca inequality urgency flag

In addition to the continuous risk score, each finding is evaluated against the Mosca inequality:

```
shelf_life + migration_time > quantum_timeline - current_year
```

| Parameter | Default | Source |
|---|---|---|
| `shelf_life` | Derived from data sensitivity classification | Public: 1yr, Internal: 5yr, Confidential: 15yr, Restricted: 25yr |
| `migration_time` | Derived from agility score (ADR-031) | Highly Agile: 1yr, Moderate: 2yr, Limited: 3yr, Rigid: 5yr |
| `quantum_timeline` | 2035 | Same as `quantum_deadline` config |

If the inequality holds → finding is flagged `URGENT` with a distinct visual indicator in the dashboard, CLI output, and IDE extensions. The urgency flag is a boolean overlay on top of the continuous risk score.

### Score interpretation

| HNDL Risk | Interpretation |
|---|---|
| 0.0 | No HNDL risk (quantum-safe or public data) |
| 0.01–0.19 | Low — monitor, no immediate action |
| 0.20–0.49 | Medium — plan migration within 2 years |
| 0.50–0.79 | High — prioritise migration |
| 0.80–1.0 | Critical — migrate immediately |

### Aggregation

- **Per-finding:** Score computed directly from the three factors
- **Per-project:** Weighted average of all finding scores, with the maximum single-finding score reported alongside to prevent averaging away critical findings
- **Per-organisation:** Weighted average across projects, with project-level maximums surfaced

---

## Options Considered

### Option A: Additive score (rejected)
`risk = data_sensitivity + quantum_vulnerability + time_factor`. Rejected because additive scoring produces non-zero risk for quantum-safe algorithms (0 + 0.4 + 0.4 = 0.8 — misleading). The multiplicative model correctly zeros risk when any factor is zero.

### Option B: Discrete risk matrix (rejected)
A 3×3×3 lookup table (Low/Medium/High for each factor). Rejected because it loses granularity — all "Medium" data sensitivity is treated identically whether it's 0.41 or 0.69. The continuous model preserves meaningful gradients for trending and comparison.

### Option C: CVSS-style vector string (rejected)
Encoding risk as a CVSS-like vector (e.g. `HNDL:S0.7/Q1.0/T0.4`). Rejected because CVSS vectors are designed for vulnerability severity, not ongoing risk exposure. The Mosca inequality provides a more theoretically grounded urgency model that security researchers recognise and trust.

---

## Consequences

- **Positive:** Continuous 0–1 risk score enables precise prioritisation and trending
- **Positive:** Multiplicative model ensures quantum-safe findings correctly score 0.0
- **Positive:** Mosca inequality flag provides a theory-backed urgency signal
- **Positive:** All parameters configurable — organisations can adjust quantum deadline and data sensitivity
- **Negative:** Data sensitivity classification requires manual configuration for accurate results (defaults to Internal)
- **Negative:** Quantum deadline is speculative — risk scores will shift as CRQC timeline estimates change
- **Negative:** Linear time factor may underweight near-term urgency — exponential curve considered but rejected for simplicity and transparency

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/06-compliance.md` | HNDL risk model referenced in compliance reporting |
| `docs/03-detection-engine.md` | Risk scoring added as post-detection enrichment step |
| `scanner/library-models/` | Quantum vulnerability classification values added to algorithm table |
| `frontend/` | Dashboard: HNDL risk heatmap, Mosca urgency flags, risk trend charts |
| `cli/internal/output/` | SARIF and text output: HNDL risk score and urgency flag per finding |
