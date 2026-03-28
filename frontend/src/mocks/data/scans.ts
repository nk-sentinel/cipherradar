export interface ScanFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file: string;
  line: number;
  finding: string;
  algorithm: string | null;
  quantum: 'vulnerable' | 'broken' | 'safe' | null;
}

export interface ScanSummary {
  id: string;
  repoId: string;
  number: number;
  branch: string;
  commit: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  duration: string;
  createdAt: string;
  status: 'completed' | 'running' | 'failed' | 'queued';
  triggerType?: 'manual' | 'schedule' | 'webhook' | 'push';
}

export interface ScanDetail extends ScanSummary {
  findings: ScanFinding[];
  algorithms: AlgorithmCount[];
}

export interface AlgorithmCount {
  name: string;
  count: number;
}

export const mockScans: ScanSummary[] = [
  {
    id: 'scan-47',
    repoId: 'repo-1',
    number: 47,
    branch: 'main',
    commit: 'a2b2fbc',
    totalFindings: 342,
    critical: 5,
    high: 28,
    medium: 67,
    low: 180,
    info: 62,
    duration: '4.2s',
    createdAt: '2026-03-19T08:00:00Z',
    status: 'completed',
    triggerType: 'manual',
  },
  {
    id: 'scan-46',
    repoId: 'repo-1',
    number: 46,
    branch: 'main',
    commit: 'f7950f8',
    totalFindings: 335,
    critical: 5,
    high: 26,
    medium: 64,
    low: 178,
    info: 62,
    duration: '4.1s',
    createdAt: '2026-03-18T10:00:00Z',
    status: 'completed',
    triggerType: 'schedule',
  },
  {
    id: 'scan-45',
    repoId: 'repo-1',
    number: 45,
    branch: 'feat/auth',
    commit: '0dd3b27',
    totalFindings: 318,
    critical: 3,
    high: 22,
    medium: 58,
    low: 172,
    info: 63,
    duration: '3.8s',
    createdAt: '2026-03-17T14:30:00Z',
    status: 'completed',
    triggerType: 'webhook',
  },
  {
    id: 'scan-44',
    repoId: 'repo-1',
    number: 44,
    branch: 'main',
    commit: 'b1c3d4e',
    totalFindings: 310,
    critical: 4,
    high: 20,
    medium: 55,
    low: 170,
    info: 61,
    duration: '3.9s',
    createdAt: '2026-03-16T09:15:00Z',
    status: 'completed',
    triggerType: 'push',
  },
  {
    id: 'scan-43',
    repoId: 'repo-1',
    number: 43,
    branch: 'fix/tls-config',
    commit: 'e5f6a7b',
    totalFindings: 305,
    critical: 6,
    high: 19,
    medium: 52,
    low: 168,
    info: 60,
    duration: '3.7s',
    createdAt: '2026-03-15T16:45:00Z',
    status: 'completed',
    triggerType: 'push',
  },
  {
    id: 'scan-42',
    repoId: 'repo-2',
    number: 42,
    branch: 'main',
    commit: '',
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    duration: '',
    createdAt: '2026-03-28T12:00:00Z',
    status: 'queued',
    triggerType: 'schedule',
  },
  {
    id: 'scan-41',
    repoId: 'repo-3',
    number: 41,
    branch: 'develop',
    commit: 'c9d1e2f',
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    duration: '',
    createdAt: '2026-03-28T11:30:00Z',
    status: 'running',
    triggerType: 'webhook',
  },
  {
    id: 'scan-40',
    repoId: 'repo-2',
    number: 40,
    branch: 'feat/oauth2',
    commit: 'a1b2c3d',
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    duration: '2.8s',
    createdAt: '2026-03-27T09:00:00Z',
    status: 'failed',
    triggerType: 'manual',
  },
  {
    id: 'scan-39',
    repoId: 'repo-4',
    number: 39,
    branch: 'main',
    commit: 'f4e5d6c',
    totalFindings: 448,
    critical: 4,
    high: 30,
    medium: 72,
    low: 256,
    info: 86,
    duration: '5.6s',
    createdAt: '2026-03-26T15:20:00Z',
    status: 'completed',
    triggerType: 'schedule',
  },
];

export const mockScanFindings: ScanFinding[] = [
  {
    id: 'f-1',
    severity: 'critical',
    file: 'SSLConfig.java',
    line: 45,
    finding: 'Certificate validation disabled',
    algorithm: null,
    quantum: 'vulnerable',
  },
  {
    id: 'f-2',
    severity: 'critical',
    file: 'jwt.js',
    line: 23,
    finding: 'JWT alg:none',
    algorithm: null,
    quantum: null,
  },
  {
    id: 'f-3',
    severity: 'critical',
    file: 'TrustStore.java',
    line: 112,
    finding: 'Empty trust manager override',
    algorithm: null,
    quantum: 'vulnerable',
  },
  {
    id: 'f-4',
    severity: 'critical',
    file: 'crypto.js',
    line: 78,
    finding: 'RC4 stream cipher usage',
    algorithm: 'RC4',
    quantum: 'broken',
  },
  {
    id: 'f-5',
    severity: 'critical',
    file: 'legacy/auth.py',
    line: 34,
    finding: 'Hardcoded private key',
    algorithm: null,
    quantum: null,
  },
  {
    id: 'f-6',
    severity: 'high',
    file: 'CryptoUtil.java',
    line: 67,
    finding: 'DES/ECB/PKCS5',
    algorithm: 'DES',
    quantum: 'broken',
  },
  {
    id: 'f-7',
    severity: 'high',
    file: 'hash.py',
    line: 12,
    finding: 'MD5 hash function',
    algorithm: 'MD5',
    quantum: 'broken',
  },
  {
    id: 'f-8',
    severity: 'high',
    file: '.env',
    line: 5,
    finding: 'Hardcoded ENCRYPTION_KEY',
    algorithm: null,
    quantum: null,
  },
  {
    id: 'f-9',
    severity: 'high',
    file: 'network/tls.py',
    line: 19,
    finding: 'TLS 1.0 usage',
    algorithm: 'TLS',
    quantum: 'vulnerable',
  },
  {
    id: 'f-10',
    severity: 'medium',
    file: 'KeyGen.java',
    line: 89,
    finding: 'RSA-2048 key generation',
    algorithm: 'RSA',
    quantum: 'vulnerable',
  },
  {
    id: 'f-11',
    severity: 'medium',
    file: 'encrypt.py',
    line: 44,
    finding: 'SHA-1 hash usage',
    algorithm: 'SHA-1',
    quantum: 'broken',
  },
  {
    id: 'f-12',
    severity: 'low',
    file: 'aes.py',
    line: 15,
    finding: 'AES-256-GCM encryption',
    algorithm: 'AES',
    quantum: 'safe',
  },
  {
    id: 'f-13',
    severity: 'info',
    file: 'config/crypto.yml',
    line: 3,
    finding: 'HMAC-SHA256 configuration',
    algorithm: 'HMAC',
    quantum: 'safe',
  },
];

export const mockAlgorithms: AlgorithmCount[] = [
  { name: 'AES', count: 89 },
  { name: 'RSA', count: 67 },
  { name: 'SHA-256', count: 54 },
  { name: 'MD5', count: 32 },
  { name: 'SHA-1', count: 28 },
  { name: 'HMAC', count: 24 },
  { name: 'DES', count: 12 },
  { name: 'RC4', count: 8 },
];

export function getScanDetail(scanId: string): ScanDetail | undefined {
  const scan = mockScans.find((s) => s.id === scanId);
  if (!scan) return undefined;
  return {
    ...scan,
    findings: mockScanFindings,
    algorithms: mockAlgorithms,
  };
}

export function getScansForRepo(repoId: string): ScanSummary[] {
  return mockScans.filter((s) => s.repoId === repoId);
}
