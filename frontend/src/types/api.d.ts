/**
 * API response types — placeholder.
 *
 * In production these will be auto-generated from the backend OpenAPI spec
 * using openapi-typescript. Do NOT hand-write types here once the generator
 * is wired up.
 */

export interface HealthResponse {
  status: string;
  version: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: {
    name: string;
    email: string;
    role: string;
    initials: string;
  };
}

export interface Repository {
  id: string;
  name: string;
  orgPath: string;
  provider: string;
  languages: string[];
  /** Mock field name */
  findings: number;
  /** API field name — takes precedence when present */
  findingsCount?: number;
  compliancePercent: number;
  quantumScore: number;
  /** Mock field name */
  lastScan: string;
  /** API field name — ISO timestamp, takes precedence when present */
  lastScanAt?: string;
}

export interface RecentScan {
  id: number;
  branch: string;
  commit: string;
  findings: number;
  critical: number;
  duration: string;
  time: string;
}

export interface AlgorithmEntry {
  name: string;
  count: number;
}

export interface LanguageEntry {
  language: string;
  count: number;
  percent: number;
}

export interface RepositoryDetail extends Repository {
  critical: number;
  quantumRisk: number;
  algorithmDistribution: AlgorithmEntry[];
  languageBreakdown: LanguageEntry[];
  recentScans: RecentScan[];
}
