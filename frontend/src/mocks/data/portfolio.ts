/**
 * Mock data for the Portfolio Dashboard — heat map, risk scores, top repos.
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface HeatMapCell {
  repoId: string;
  repoName: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TopRiskyRepo {
  repoId: string;
  repoName: string;
  provider: string;
  findings: number;
  critical: number;
  quantumRisk: number;
  compliancePercent: number;
  lastScan: string;
}

export interface SeverityDistribution {
  severity: SeverityLevel;
  count: number;
}

export interface PortfolioSummaryData {
  totalFindings: number;
  totalRepos: number;
  criticalPlusHigh: number;
  affectedRepos: number;
  quantumExposed: number;
  quantumExposedPercent: number;
  complianceAvg: number;
  complianceFramework: string;
  quantumReadinessPercent: number;
  lastScanTime: string;
  severityDistribution: SeverityDistribution[];
  topRiskRepos: TopRiskyRepo[];
}

export interface HeatMapGroup {
  id?: string;
  name: string;
  projectCount?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  infoCount?: number;
}

export interface HeatMapData {
  repos?: HeatMapCell[];
  groups?: HeatMapGroup[];
}

export const MOCK_PORTFOLIO_SUMMARY: PortfolioSummaryData = {
  totalFindings: 1247,
  totalRepos: 8,
  criticalPlusHigh: 89,
  affectedRepos: 5,
  quantumExposed: 312,
  quantumExposedPercent: 42,
  complianceAvg: 72,
  complianceFramework: 'NIST 800-131A',
  quantumReadinessPercent: 58,
  lastScanTime: '2min ago',
  severityDistribution: [
    { severity: 'critical', count: 12 },
    { severity: 'high', count: 77 },
    { severity: 'medium', count: 234 },
    { severity: 'low', count: 156 },
    { severity: 'info', count: 768 },
  ],
  topRiskRepos: [
    {
      repoId: 'repo-4',
      repoName: 'mobile-backend',
      provider: 'Bitbucket',
      findings: 456,
      critical: 3,
      quantumRisk: 68,
      compliancePercent: 45,
      lastScan: '1d ago',
    },
    {
      repoId: 'repo-1',
      repoName: 'payment-service',
      provider: 'GitHub',
      findings: 342,
      critical: 5,
      quantumRisk: 72,
      compliancePercent: 65,
      lastScan: '2h ago',
    },
    {
      repoId: 'repo-2',
      repoName: 'auth-api',
      provider: 'GitHub',
      findings: 187,
      critical: 2,
      quantumRisk: 54,
      compliancePercent: 82,
      lastScan: '3h ago',
    },
    {
      repoId: 'repo-3',
      repoName: 'data-pipeline',
      provider: 'GitLab',
      findings: 98,
      critical: 0,
      quantumRisk: 22,
      compliancePercent: 94,
      lastScan: '5h ago',
    },
    {
      repoId: 'repo-5',
      repoName: 'api-gateway',
      provider: 'GitHub',
      findings: 64,
      critical: 1,
      quantumRisk: 38,
      compliancePercent: 78,
      lastScan: '6h ago',
    },
    {
      repoId: 'repo-6',
      repoName: 'user-service',
      provider: 'GitHub',
      findings: 42,
      critical: 0,
      quantumRisk: 30,
      compliancePercent: 85,
      lastScan: '8h ago',
    },
    {
      repoId: 'repo-7',
      repoName: 'notification-svc',
      provider: 'GitLab',
      findings: 34,
      critical: 0,
      quantumRisk: 18,
      compliancePercent: 91,
      lastScan: '12h ago',
    },
    {
      repoId: 'repo-8',
      repoName: 'config-service',
      provider: 'GitHub',
      findings: 24,
      critical: 0,
      quantumRisk: 12,
      compliancePercent: 96,
      lastScan: '1d ago',
    },
  ],
};

export const MOCK_HEAT_MAP: HeatMapData = {
  repos: [
    { repoId: 'repo-1', repoName: 'payment-service', critical: 5, high: 28, medium: 67, low: 42, info: 200 },
    { repoId: 'repo-2', repoName: 'auth-api', critical: 2, high: 12, medium: 38, low: 35, info: 100 },
    { repoId: 'repo-3', repoName: 'data-pipeline', critical: 0, high: 4, medium: 18, low: 26, info: 50 },
    { repoId: 'repo-4', repoName: 'mobile-backend', critical: 3, high: 22, medium: 68, low: 33, info: 330 },
    { repoId: 'repo-5', repoName: 'api-gateway', critical: 1, high: 6, medium: 22, low: 12, info: 23 },
    { repoId: 'repo-6', repoName: 'user-service', critical: 0, high: 3, medium: 12, low: 8, info: 19 },
    { repoId: 'repo-7', repoName: 'notification-svc', critical: 0, high: 2, medium: 8, low: 6, info: 18 },
    { repoId: 'repo-8', repoName: 'config-service', critical: 1, high: 0, medium: 1, low: 4, info: 18 },
  ],
};

export function getPortfolioSummary(): PortfolioSummaryData {
  return MOCK_PORTFOLIO_SUMMARY;
}

export function getHeatMap(): HeatMapData {
  return MOCK_HEAT_MAP;
}
