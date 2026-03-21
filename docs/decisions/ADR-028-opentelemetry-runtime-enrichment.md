# ADR-028: OpenTelemetry Runtime Enrichment — Collector Exporter Plugin

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

CipherRadar's static analysis (Passes 1–3) identifies cryptographic assets in source code. However, runtime behaviour can differ from static findings — applications may negotiate different TLS cipher suites depending on the peer, load cryptographic libraries dynamically, or use configuration-driven algorithm selection that is invisible to static analysis.

OpenTelemetry (OTel) is the industry standard for distributed tracing and has been widely adopted in enterprise environments. OTel spans already carry TLS and cryptographic metadata as semantic convention attributes. Rather than building a custom runtime agent, CipherRadar can consume this existing telemetry data to enrich static CBOM findings with runtime observations.

---

## Decision

### OTel Collector exporter plugin

A custom OpenTelemetry Collector exporter plugin written in Go. Customers add CipherRadar as an additional export destination in their existing OTel Collector configuration — no changes to application instrumentation required.

```yaml
# Customer's otel-collector-config.yaml
exporters:
  cradar:
    endpoint: "https://cradar.internal/api/v1/runtime/enrich"
    api_key: "${CRADAR_API_KEY}"
    project: "payment-service"

service:
  pipelines:
    traces:
      exporters: [jaeger, cradar]  # Add cradar alongside existing exporters
```

### Attribute filtering

The exporter filters spans for cryptographic-relevant attributes before forwarding. Only spans containing at least one of these attributes are sent to CipherRadar:

| OTel Attribute | Semantic Convention | What It Captures |
|---|---|---|
| `tls.protocol.version` | Stable | TLS version negotiated (e.g. `1.2`, `1.3`) |
| `tls.cipher_suite` | Stable | Cipher suite negotiated (e.g. `TLS_AES_256_GCM_SHA384`) |
| `net.sock.peer.cert` | Experimental | Peer certificate chain (DER-encoded) |
| `tls.client.certificate` | Experimental | Client certificate presented |
| `tls.server.certificate` | Experimental | Server certificate presented |

All other spans are dropped at the exporter — CipherRadar never receives non-cryptographic telemetry data. This minimises data transfer and addresses privacy concerns.

### Backend enrichment endpoint

`POST /api/v1/runtime/enrich` receives filtered span data and links runtime observations to static CBOM findings:

1. Extract service name + algorithm/cipher from span attributes
2. Match against existing CBOM findings by `service` + `algorithm` composite key
3. Create `runtime_observations` records linking to `findings` with timestamp, observed cipher suite, TLS version, and certificate metadata
4. Flag discrepancies: static finding says TLS 1.2 but runtime shows TLS 1.3 negotiation → informational note. Static finding says AES-128 but runtime shows AES-256 → update confidence.

### Deployment model

The exporter plugin is distributed as:
- A standalone binary (Go plugin for the OTel Collector)
- A Docker image extending the official `otel/opentelemetry-collector-contrib` image with the CipherRadar exporter pre-installed

---

## Options Considered

### Option A: Custom runtime agent (rejected)
A CipherRadar-specific agent that hooks into TLS libraries (OpenSSL, BoringSSL, Java JSSE) at the application level. Rejected because it requires per-application deployment, language-specific integration, and duplicates what OTel already provides. Enterprise customers with existing OTel infrastructure would need to run two observability systems.

### Option B: eBPF-based TLS interception (rejected)
Kernel-level eBPF probes that intercept TLS handshakes. Provides the richest data but requires privileged access (root/CAP_BPF), is Linux-only, and is operationally complex to deploy in enterprise environments. May be revisited as an advanced option in a future phase.

### Option C: Log parsing (rejected)
Parse application logs for TLS/crypto-related entries. Too fragile — log formats vary across frameworks, languages, and versions. No standardised schema. High false positive rate.

---

## Consequences

- **Positive:** Zero-instrumentation deployment for customers with existing OTel infrastructure
- **Positive:** Minimal data transfer — only crypto-relevant spans forwarded
- **Positive:** Runtime observations enrich static CBOM with real-world behaviour data
- **Positive:** Standard OTel Collector plugin model — familiar to operations teams
- **Negative:** Depends on applications being instrumented with OTel (not universal yet)
- **Negative:** Only captures TLS-level crypto — does not observe application-level encryption (e.g. field-level AES)
- **Negative:** Experimental OTel attributes (`net.sock.peer.cert`) may change in future semantic convention versions

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/02-architecture.md` | Runtime enrichment component added to architecture diagram |
| `docs/07-tech-stack.md` | OTel Collector SDK (Go) added |
| `docs/12-phase2-implementation-plan.md` | No change — this is Phase 4 |
| `backend/` | New `POST /api/v1/runtime/enrich` endpoint; `runtime_observations` table |
