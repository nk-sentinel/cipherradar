export type CVESeverity = 'critical' | 'high' | 'medium' | 'low';
export type CVEStatus = 'fixed' | 'unfixed';

export interface CVECorrelationEntry {
  id: string;
  library: string;
  libraryVersion: string;
  cveId: string;
  cveSeverity: CVESeverity;
  cveStatus: CVEStatus;
  fixedInVersion: string | null;
  cryptoFindingId: string;
  cryptoFindingTitle: string;
  affectedVersions: string;
}

export interface CVECorrelationData {
  entries: CVECorrelationEntry[];
  totalCves: number;
  criticalCount: number;
  highCount: number;
  unfixedCount: number;
}

export const MOCK_CVE_CORRELATION: CVECorrelationData = {
  entries: [
    {
      id: 'cve-link-001',
      library: 'openssl',
      libraryVersion: '1.1.1k',
      cveId: 'CVE-2024-5535',
      cveSeverity: 'critical',
      cveStatus: 'fixed',
      fixedInVersion: '1.1.1w',
      cryptoFindingId: 'f-007',
      cryptoFindingTitle: 'CERT_NONE — SSL verification disabled',
      affectedVersions: '1.1.1 - 1.1.1v',
    },
    {
      id: 'cve-link-002',
      library: 'pycryptodome',
      libraryVersion: '3.15.0',
      cveId: 'CVE-2023-52323',
      cveSeverity: 'high',
      cveStatus: 'fixed',
      fixedInVersion: '3.19.1',
      cryptoFindingId: 'f-003',
      cryptoFindingTitle: 'DES/ECB — broken cipher',
      affectedVersions: '3.1.0 - 3.19.0',
    },
    {
      id: 'cve-link-003',
      library: 'bouncy-castle',
      libraryVersion: '1.70',
      cveId: 'CVE-2024-34447',
      cveSeverity: 'medium',
      cveStatus: 'unfixed',
      fixedInVersion: null,
      cryptoFindingId: 'f-006',
      cryptoFindingTitle: 'RSA-2048 key generation',
      affectedVersions: '1.68 - 1.77',
    },
    {
      id: 'cve-link-004',
      library: 'python-jose',
      libraryVersion: '3.3.0',
      cveId: 'CVE-2024-33663',
      cveSeverity: 'high',
      cveStatus: 'unfixed',
      fixedInVersion: null,
      cryptoFindingId: 'f-004',
      cryptoFindingTitle: 'SHA-1 signature verification',
      affectedVersions: '3.0.0 - 3.3.0',
    },
    {
      id: 'cve-link-005',
      library: 'cryptography',
      libraryVersion: '41.0.4',
      cveId: 'CVE-2024-26130',
      cveSeverity: 'low',
      cveStatus: 'fixed',
      fixedInVersion: '42.0.0',
      cryptoFindingId: 'f-008',
      cryptoFindingTitle: 'AES-256-GCM encryption',
      affectedVersions: '38.0.0 - 41.0.7',
    },
    {
      id: 'cve-link-006',
      library: 'openssl',
      libraryVersion: '1.1.1k',
      cveId: 'CVE-2024-0727',
      cveSeverity: 'medium',
      cveStatus: 'fixed',
      fixedInVersion: '1.1.1x',
      cryptoFindingId: 'f-001',
      cryptoFindingTitle: 'Certificate validation disabled',
      affectedVersions: '1.0.2 - 1.1.1w',
    },
  ],
  totalCves: 6,
  criticalCount: 1,
  highCount: 2,
  unfixedCount: 2,
};

export function getCVECorrelation(_projectId: string): CVECorrelationData {
  return MOCK_CVE_CORRELATION;
}
