/**
 * Mock data for compliance views (portfolio-level and per-repo).
 */

export type ComplianceStatus = 'disallowed' | 'deprecated' | 'acceptable';

export interface FrameworkScore {
  framework: string;
  score: number;
  description?: string;
}

export interface RepoComplianceRow {
  repoId: string;
  repoName: string;
  nist: number;
  fips: number;
  cnsa: number;
  disallowed: number;
}

export interface NonCompliantItem {
  status: ComplianceStatus;
  algorithm: string;
  classification: string;
  count: number;
  action: string;
}

export interface PortfolioComplianceData {
  frameworks: FrameworkScore[];
  repoCompliance: RepoComplianceRow[];
}

export interface RepoComplianceData {
  repoId: string;
  frameworks: FrameworkScore[];
  nonCompliantItems: NonCompliantItem[];
}

export const MOCK_PORTFOLIO_COMPLIANCE: PortfolioComplianceData = {
  frameworks: [
    { framework: 'NIST 800-131A', score: 72, description: 'Org average' },
    { framework: 'FIPS 140-3', score: 65, description: 'Org average' },
    { framework: 'CNSA 2.0', score: 38, description: 'Org average' },
  ],
  repoCompliance: [
    { repoId: 'repo-3', repoName: 'data-pipeline', nist: 94, fips: 91, cnsa: 62, disallowed: 0 },
    { repoId: 'repo-2', repoName: 'auth-api', nist: 82, fips: 75, cnsa: 45, disallowed: 2 },
    { repoId: 'repo-1', repoName: 'payment-service', nist: 65, fips: 58, cnsa: 30, disallowed: 8 },
    { repoId: 'repo-4', repoName: 'mobile-backend', nist: 45, fips: 38, cnsa: 22, disallowed: 14 },
  ],
};

export const MOCK_REPO_COMPLIANCE: Record<string, RepoComplianceData> = {
  'repo-1': {
    repoId: 'repo-1',
    frameworks: [
      { framework: 'NIST 800-131A', score: 65 },
      { framework: 'FIPS 140-3', score: 58 },
      { framework: 'CNSA 2.0', score: 30 },
    ],
    nonCompliantItems: [
      { status: 'disallowed', algorithm: 'DES', classification: 'Disallowed after 2023', count: 4, action: 'Replace with AES-256' },
      { status: 'deprecated', algorithm: 'SHA-1', classification: 'Deprecated for signatures', count: 12, action: 'Migrate to SHA-256' },
      { status: 'acceptable', algorithm: 'AES-256', classification: 'Acceptable', count: 89, action: 'No action' },
    ],
  },
  'repo-2': {
    repoId: 'repo-2',
    frameworks: [
      { framework: 'NIST 800-131A', score: 82 },
      { framework: 'FIPS 140-3', score: 75 },
      { framework: 'CNSA 2.0', score: 45 },
    ],
    nonCompliantItems: [
      { status: 'deprecated', algorithm: 'SHA-1', classification: 'Deprecated for signatures', count: 2, action: 'Migrate to SHA-256' },
      { status: 'acceptable', algorithm: 'AES-256', classification: 'Acceptable', count: 45, action: 'No action' },
    ],
  },
  'repo-3': {
    repoId: 'repo-3',
    frameworks: [
      { framework: 'NIST 800-131A', score: 94 },
      { framework: 'FIPS 140-3', score: 91 },
      { framework: 'CNSA 2.0', score: 62 },
    ],
    nonCompliantItems: [
      { status: 'acceptable', algorithm: 'AES-256', classification: 'Acceptable', count: 34, action: 'No action' },
      { status: 'acceptable', algorithm: 'SHA-256', classification: 'Acceptable', count: 28, action: 'No action' },
    ],
  },
  'repo-4': {
    repoId: 'repo-4',
    frameworks: [
      { framework: 'NIST 800-131A', score: 45 },
      { framework: 'FIPS 140-3', score: 38 },
      { framework: 'CNSA 2.0', score: 22 },
    ],
    nonCompliantItems: [
      { status: 'disallowed', algorithm: 'DES', classification: 'Disallowed after 2023', count: 8, action: 'Replace with AES-256' },
      { status: 'disallowed', algorithm: 'MD5', classification: 'Disallowed', count: 6, action: 'Replace with SHA-256' },
      { status: 'deprecated', algorithm: 'SHA-1', classification: 'Deprecated for signatures', count: 18, action: 'Migrate to SHA-256' },
      { status: 'acceptable', algorithm: 'AES-256', classification: 'Acceptable', count: 95, action: 'No action' },
    ],
  },
};

export function getPortfolioCompliance(): PortfolioComplianceData {
  return MOCK_PORTFOLIO_COMPLIANCE;
}

export function getRepoCompliance(repoId: string): RepoComplianceData | undefined {
  return MOCK_REPO_COMPLIANCE[repoId];
}
