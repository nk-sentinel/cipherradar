/**
 * Mock data for the enhanced Compliance Dashboard view.
 * 6 framework score cards with trend data, CNSA 2.0 timeline, cross-repo comparison.
 */

export interface FrameworkScoreCard {
  id: string;
  framework: string;
  shortName: string;
  score: number;
  previousScore: number;
  trend: number[]; // last 12 data points (months)
  totalFindings: number;
  compliantFindings: number;
  description: string;
}

export interface CNSATimelineItem {
  id: string;
  label: string;
  deadline: string; // ISO date
  status: 'completed' | 'in-progress' | 'upcoming' | 'overdue';
  description: string;
  progress: number; // 0-100
}

export interface RepoComparisonRow {
  repoId: string;
  repoName: string;
  scores: Record<string, number>; // frameworkId -> score
}

export interface ComplianceDashboardData {
  frameworks: FrameworkScoreCard[];
  cnsaTimeline: CNSATimelineItem[];
  repoComparison: RepoComparisonRow[];
}

export const MOCK_COMPLIANCE_DASHBOARD: ComplianceDashboardData = {
  frameworks: [
    {
      id: 'nist-800-131a',
      framework: 'NIST 800-131A',
      shortName: 'NIST',
      score: 72,
      previousScore: 65,
      trend: [45, 48, 52, 55, 58, 60, 62, 65, 65, 68, 70, 72],
      totalFindings: 1247,
      compliantFindings: 898,
      description: 'Transitioning the Use of Cryptographic Algorithms',
    },
    {
      id: 'fips-140-3',
      framework: 'FIPS 140-3',
      shortName: 'FIPS',
      score: 65,
      previousScore: 60,
      trend: [38, 40, 42, 45, 48, 50, 52, 55, 58, 60, 62, 65],
      totalFindings: 1247,
      compliantFindings: 811,
      description: 'Security Requirements for Cryptographic Modules',
    },
    {
      id: 'pci-dss-v4',
      framework: 'PCI-DSS v4.0',
      shortName: 'PCI',
      score: 78,
      previousScore: 74,
      trend: [55, 58, 60, 62, 65, 68, 70, 72, 74, 74, 76, 78],
      totalFindings: 456,
      compliantFindings: 356,
      description: 'Payment Card Industry Data Security Standard',
    },
    {
      id: 'cnsa-2',
      framework: 'CNSA 2.0',
      shortName: 'CNSA',
      score: 38,
      previousScore: 30,
      trend: [12, 14, 16, 18, 20, 22, 25, 28, 30, 32, 35, 38],
      totalFindings: 1247,
      compliantFindings: 474,
      description: 'Commercial National Security Algorithm Suite',
    },
    {
      id: 'iso-27001-a8-24',
      framework: 'ISO 27001 A.8.24',
      shortName: 'ISO',
      score: 82,
      previousScore: 80,
      trend: [60, 62, 65, 68, 70, 72, 74, 76, 78, 80, 80, 82],
      totalFindings: 890,
      compliantFindings: 730,
      description: 'Use of Cryptography Control',
    },
    {
      id: 'eu-cra',
      framework: 'EU CRA',
      shortName: 'CRA',
      score: 55,
      previousScore: 48,
      trend: [20, 22, 25, 28, 32, 35, 38, 42, 45, 48, 52, 55],
      totalFindings: 678,
      compliantFindings: 373,
      description: 'EU Cyber Resilience Act',
    },
  ],
  cnsaTimeline: [
    {
      id: 'cnsa-t1',
      label: 'Deprecate RSA/ECDSA for firmware signing',
      deadline: '2025-12-31',
      status: 'overdue',
      description: 'All firmware and software signing must transition to ML-DSA.',
      progress: 45,
    },
    {
      id: 'cnsa-t2',
      label: 'Transition to ML-KEM for key establishment',
      deadline: '2026-12-31',
      status: 'in-progress',
      description: 'All key encapsulation must migrate from RSA/ECDH to ML-KEM (FIPS 203).',
      progress: 30,
    },
    {
      id: 'cnsa-t3',
      label: 'Adopt ML-DSA for digital signatures',
      deadline: '2027-06-30',
      status: 'in-progress',
      description: 'All digital signatures must use ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).',
      progress: 18,
    },
    {
      id: 'cnsa-t4',
      label: 'Deprecate all pre-quantum key exchange',
      deadline: '2028-12-31',
      status: 'upcoming',
      description: 'RSA, DH, ECDH fully deprecated for all uses.',
      progress: 5,
    },
    {
      id: 'cnsa-t5',
      label: 'Full CNSA 2.0 compliance required',
      deadline: '2030-12-31',
      status: 'upcoming',
      description: 'All NSS systems must be fully compliant with CNSA 2.0 suite.',
      progress: 0,
    },
  ],
  repoComparison: [
    {
      repoId: 'repo-1',
      repoName: 'payment-service',
      scores: {
        'nist-800-131a': 65,
        'fips-140-3': 58,
        'pci-dss-v4': 82,
        'cnsa-2': 30,
        'iso-27001-a8-24': 78,
        'eu-cra': 50,
      },
    },
    {
      repoId: 'repo-2',
      repoName: 'auth-api',
      scores: {
        'nist-800-131a': 82,
        'fips-140-3': 75,
        'pci-dss-v4': 88,
        'cnsa-2': 45,
        'iso-27001-a8-24': 85,
        'eu-cra': 62,
      },
    },
    {
      repoId: 'repo-3',
      repoName: 'data-pipeline',
      scores: {
        'nist-800-131a': 94,
        'fips-140-3': 91,
        'pci-dss-v4': 95,
        'cnsa-2': 62,
        'iso-27001-a8-24': 92,
        'eu-cra': 78,
      },
    },
    {
      repoId: 'repo-4',
      repoName: 'mobile-backend',
      scores: {
        'nist-800-131a': 45,
        'fips-140-3': 38,
        'pci-dss-v4': 48,
        'cnsa-2': 22,
        'iso-27001-a8-24': 72,
        'eu-cra': 35,
      },
    },
  ],
};

export function getComplianceDashboard(): ComplianceDashboardData {
  return MOCK_COMPLIANCE_DASHBOARD;
}
