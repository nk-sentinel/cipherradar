/**
 * Mock data for quantum readiness views (portfolio-level and per-repo).
 */

export type QuantumPriority = 'critical' | 'high' | 'medium' | 'low';

export interface MigrationItem {
  algorithm: string;
  count: number;
  repos: number;
  migrateTo: string;
  priority: QuantumPriority;
}

export interface RepoQuantumRisk {
  repoId: string;
  repoName: string;
  riskScore: number;
  vulnerable: number;
  safe: number;
}

export interface QuantumStatusBreakdown {
  vulnerable: number;
  safe: number;
  unknown: number;
  broken: number;
}

export interface PortfolioQuantumData {
  riskScore: number;
  vulnerableCount: number;
  migrationEffort: string;
  migrationPriorities: MigrationItem[];
  repoRisks: RepoQuantumRisk[];
  statusBreakdown: QuantumStatusBreakdown;
}

export interface RepoQuantumData {
  repoId: string;
  riskScore: number;
  vulnerableCount: number;
  safeCount: number;
  migrationPriorities: MigrationItem[];
}

export const MOCK_PORTFOLIO_QUANTUM: PortfolioQuantumData = {
  riskScore: 58,
  vulnerableCount: 312,
  migrationEffort: '~6mo',
  migrationPriorities: [
    { algorithm: 'RSA', count: 134, repos: 7, migrateTo: 'ML-KEM / ML-DSA', priority: 'critical' },
    { algorithm: 'ECDSA', count: 67, repos: 5, migrateTo: 'ML-DSA', priority: 'high' },
    { algorithm: 'ECDH', count: 45, repos: 4, migrateTo: 'ML-KEM', priority: 'high' },
    { algorithm: 'Ed25519', count: 34, repos: 3, migrateTo: 'ML-DSA', priority: 'medium' },
    { algorithm: 'DH', count: 22, repos: 2, migrateTo: 'ML-KEM', priority: 'medium' },
  ],
  repoRisks: [
    { repoId: 'repo-1', repoName: 'payment-service', riskScore: 72, vulnerable: 67, safe: 89 },
    { repoId: 'repo-4', repoName: 'mobile-backend', riskScore: 68, vulnerable: 128, safe: 45 },
    { repoId: 'repo-2', repoName: 'auth-api', riskScore: 54, vulnerable: 34, safe: 67 },
    { repoId: 'repo-3', repoName: 'data-pipeline', riskScore: 22, vulnerable: 8, safe: 52 },
  ],
  statusBreakdown: {
    vulnerable: 42,
    safe: 38,
    unknown: 12,
    broken: 8,
  },
};

export const MOCK_REPO_QUANTUM: Record<string, RepoQuantumData> = {
  'repo-1': {
    repoId: 'repo-1',
    riskScore: 72,
    vulnerableCount: 67,
    safeCount: 89,
    migrationPriorities: [
      { algorithm: 'RSA', count: 42, repos: 1, migrateTo: 'ML-KEM / ML-DSA', priority: 'critical' },
      { algorithm: 'ECDSA', count: 15, repos: 1, migrateTo: 'ML-DSA', priority: 'high' },
      { algorithm: 'ECDH', count: 10, repos: 1, migrateTo: 'ML-KEM', priority: 'high' },
    ],
  },
  'repo-2': {
    repoId: 'repo-2',
    riskScore: 54,
    vulnerableCount: 34,
    safeCount: 67,
    migrationPriorities: [
      { algorithm: 'RSA', count: 22, repos: 1, migrateTo: 'ML-KEM / ML-DSA', priority: 'critical' },
      { algorithm: 'ECDSA', count: 8, repos: 1, migrateTo: 'ML-DSA', priority: 'high' },
      { algorithm: 'Ed25519', count: 4, repos: 1, migrateTo: 'ML-DSA', priority: 'medium' },
    ],
  },
  'repo-3': {
    repoId: 'repo-3',
    riskScore: 22,
    vulnerableCount: 8,
    safeCount: 52,
    migrationPriorities: [
      { algorithm: 'RSA', count: 6, repos: 1, migrateTo: 'ML-KEM / ML-DSA', priority: 'high' },
      { algorithm: 'ECDSA', count: 2, repos: 1, migrateTo: 'ML-DSA', priority: 'medium' },
    ],
  },
  'repo-4': {
    repoId: 'repo-4',
    riskScore: 68,
    vulnerableCount: 128,
    safeCount: 45,
    migrationPriorities: [
      { algorithm: 'RSA', count: 64, repos: 1, migrateTo: 'ML-KEM / ML-DSA', priority: 'critical' },
      { algorithm: 'ECDSA', count: 42, repos: 1, migrateTo: 'ML-DSA', priority: 'high' },
      { algorithm: 'ECDH', count: 22, repos: 1, migrateTo: 'ML-KEM', priority: 'high' },
    ],
  },
};

export function getPortfolioQuantum(): PortfolioQuantumData {
  return MOCK_PORTFOLIO_QUANTUM;
}

export function getRepoQuantum(repoId: string): RepoQuantumData | undefined {
  return MOCK_REPO_QUANTUM[repoId];
}
