/**
 * SARIF 2.1.0 types (subset used by CipherRadar).
 *
 * Full spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

// ---------------------------------------------------------------------------
// SARIF structures
// ---------------------------------------------------------------------------

export interface SarifLog {
  version: string;
  $schema?: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
}

export interface SarifTool {
  driver: SarifToolComponent;
}

export interface SarifToolComponent {
  name: string;
  version?: string;
  rules?: SarifReportingDescriptor[];
}

export interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: SarifMessage;
  fullDescription?: SarifMessage;
  helpUri?: string;
  properties?: Record<string, unknown>;
}

export interface SarifMessage {
  text: string;
}

export interface SarifResult {
  ruleId: string;
  level?: SarifLevel;
  message: SarifMessage;
  locations?: SarifLocation[];
  properties?: SarifResultProperties;
}

export type SarifLevel = "error" | "warning" | "note" | "none";

export interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
}

export interface SarifPhysicalLocation {
  artifactLocation?: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifArtifactLocation {
  uri?: string;
  uriBaseId?: string;
}

export interface SarifRegion {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

// ---------------------------------------------------------------------------
// CipherRadar-specific properties embedded in SARIF result.properties
// ---------------------------------------------------------------------------

export interface SarifResultProperties {
  /** Algorithm or protocol name (e.g. "AES-256-GCM", "RSA-2048") */
  algorithmName?: string;

  /** Cryptographic asset type: symmetric, asymmetric, hash, kdf, mac, protocol, certificate, key */
  algorithmFamily?: string;

  /** Quantum security assessment */
  quantumStatus?: QuantumStatus;

  /** Recommended post-quantum replacement */
  pqcReplacement?: string;

  /** Compliance framework tags (e.g. ["NIST", "FIPS-140-3"]) */
  complianceTags?: string[];

  /** CipherRadar finding ID (for backend API calls) */
  findingId?: string;

  /** Remediation hint text */
  remediationHint?: string;
}

export type QuantumStatus = "safe" | "vulnerable" | "unknown";

// ---------------------------------------------------------------------------
// Internal finding representation
// ---------------------------------------------------------------------------

export interface CipherRadarFinding {
  /** SARIF rule ID (e.g. "cbom-java-weak-hash") */
  ruleId: string;

  /** Human-readable message */
  message: string;

  /** Diagnostic severity mapped from SARIF level */
  severity: FindingSeverity;

  /** File URI */
  fileUri: string;

  /** 0-based line/column range */
  range: FindingRange;

  /** Algorithm name */
  algorithmName?: string;

  /** Algorithm family */
  algorithmFamily?: string;

  /** Quantum security status */
  quantumStatus?: QuantumStatus;

  /** PQC replacement suggestion */
  pqcReplacement?: string;

  /** Compliance tags */
  complianceTags?: string[];

  /** Backend finding ID */
  findingId?: string;

  /** Short remediation hint */
  remediationHint?: string;
}

export type FindingSeverity = "error" | "warning" | "information" | "hint";

export interface FindingRange {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

// ---------------------------------------------------------------------------
// Extension configuration
// ---------------------------------------------------------------------------

export interface CipherRadarConfig {
  cradarPath: string;
  autoScan: boolean;
  apiUrl: string;
  apiKey: string;
  severityMinLevel: FindingSeverity;
}
