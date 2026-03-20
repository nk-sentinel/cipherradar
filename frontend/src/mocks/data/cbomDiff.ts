/**
 * Mock data for the CBOM Diff view.
 */

export type DiffType = 'added' | 'removed' | 'changed' | 'unchanged';
export type DiffSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ScanSelector {
  scanId: string;
  scanNumber: number;
  date: string; // ISO date string
  branch: string;
  commit: string;
  totalFindings: number;
}

export interface DiffItem {
  id: string;
  diffType: DiffType;
  component: string;
  file: string;
  line: number;
  severity: DiffSeverity;
  type: string; // algorithm, protocol, certificate, key
  oldValue?: string;
  newValue?: string;
  details: string;
}

export interface DiffSummary {
  added: number;
  removed: number;
  changed: number;
  unchanged: number;
}

export interface CBOMDiffData {
  baseScan: ScanSelector;
  targetScan: ScanSelector;
  summary: DiffSummary;
  items: DiffItem[];
}

export const MOCK_SCAN_SELECTORS: ScanSelector[] = [
  { scanId: 'scan-47', scanNumber: 47, date: '2026-03-20T14:30:00Z', branch: 'main', commit: 'a2b2fbc', totalFindings: 342 },
  { scanId: 'scan-46', scanNumber: 46, date: '2026-03-19T10:15:00Z', branch: 'main', commit: 'f7950f8', totalFindings: 335 },
  { scanId: 'scan-45', scanNumber: 45, date: '2026-03-17T16:45:00Z', branch: 'feat/auth', commit: '0dd3b27', totalFindings: 318 },
  { scanId: 'scan-44', scanNumber: 44, date: '2026-03-15T09:20:00Z', branch: 'main', commit: 'b5c4d3e', totalFindings: 330 },
  { scanId: 'scan-43', scanNumber: 43, date: '2026-03-13T11:00:00Z', branch: 'fix/tls', commit: 'e8f9a0b', totalFindings: 340 },
];

export const MOCK_DIFF_ITEMS: DiffItem[] = [
  {
    id: 'diff-1',
    diffType: 'added',
    component: 'PBKDF2-SHA256',
    file: 'auth/password.py',
    line: 22,
    severity: 'info',
    type: 'algorithm',
    newValue: 'PBKDF2-SHA256 (iterations=600000)',
    details: 'New key derivation function added for password hashing',
  },
  {
    id: 'diff-2',
    diffType: 'added',
    component: 'AES-256-GCM',
    file: 'crypto/encrypt.py',
    line: 15,
    severity: 'info',
    type: 'algorithm',
    newValue: 'AES-256-GCM',
    details: 'New authenticated encryption implementation',
  },
  {
    id: 'diff-3',
    diffType: 'added',
    component: 'Argon2id',
    file: 'auth/password_v2.py',
    line: 8,
    severity: 'info',
    type: 'algorithm',
    newValue: 'Argon2id (m=65536, t=3, p=4)',
    details: 'Modern password hashing with memory-hard KDF',
  },
  {
    id: 'diff-4',
    diffType: 'added',
    component: 'TLS 1.3 config',
    file: 'network/tls.py',
    line: 5,
    severity: 'info',
    type: 'protocol',
    newValue: 'TLS 1.3 (TLS_AES_256_GCM_SHA384)',
    details: 'Explicit TLS 1.3 cipher suite configuration',
  },
  {
    id: 'diff-5',
    diffType: 'added',
    component: 'ECDSA-P384 signing key',
    file: 'certs/signing.py',
    line: 12,
    severity: 'medium',
    type: 'key',
    newValue: 'ECDSA P-384',
    details: 'New signing key (quantum-vulnerable)',
  },
  {
    id: 'diff-6',
    diffType: 'added',
    component: 'HMAC-SHA512',
    file: 'api/middleware.py',
    line: 34,
    severity: 'info',
    type: 'algorithm',
    newValue: 'HMAC-SHA512',
    details: 'API request signature validation',
  },
  {
    id: 'diff-7',
    diffType: 'added',
    component: 'Ed25519 verification',
    file: 'auth/ssh.py',
    line: 20,
    severity: 'medium',
    type: 'algorithm',
    newValue: 'Ed25519',
    details: 'SSH public key verification (quantum-vulnerable)',
  },
  {
    id: 'diff-8',
    diffType: 'removed',
    component: 'MD5',
    file: 'crypto/legacy.py',
    line: 8,
    severity: 'high',
    type: 'algorithm',
    oldValue: 'MD5 hash',
    details: 'Legacy hash function removed - security improvement',
  },
  {
    id: 'diff-9',
    diffType: 'removed',
    component: 'DES/ECB',
    file: 'crypto/old_cipher.py',
    line: 15,
    severity: 'critical',
    type: 'algorithm',
    oldValue: 'DES/ECB/PKCS5Padding',
    details: 'Broken cipher removed - security improvement',
  },
  {
    id: 'diff-10',
    diffType: 'removed',
    component: 'Hardcoded API_SECRET',
    file: 'config/settings.py',
    line: 12,
    severity: 'critical',
    type: 'key',
    oldValue: 'API_SECRET="changeme123"',
    details: 'Hardcoded secret removed - moved to vault',
  },
  {
    id: 'diff-11',
    diffType: 'changed',
    component: 'RSA key size',
    file: 'keys/gen.py',
    line: 5,
    severity: 'medium',
    type: 'key',
    oldValue: 'RSA-2048',
    newValue: 'RSA-4096',
    details: 'Key size upgraded (still quantum-vulnerable)',
  },
  {
    id: 'diff-12',
    diffType: 'changed',
    component: 'TLS version',
    file: 'network/cfg.py',
    line: 10,
    severity: 'low',
    type: 'protocol',
    oldValue: 'TLS 1.0',
    newValue: 'TLS 1.3',
    details: 'Protocol upgraded from deprecated to current',
  },
  {
    id: 'diff-13',
    diffType: 'changed',
    component: 'Password hashing',
    file: 'auth/hash.py',
    line: 30,
    severity: 'info',
    type: 'algorithm',
    oldValue: 'PBKDF2 (iterations=100000)',
    newValue: 'PBKDF2 (iterations=600000)',
    details: 'Iteration count increased per OWASP recommendation',
  },
  {
    id: 'diff-14',
    diffType: 'changed',
    component: 'JWT algorithm',
    file: 'auth/jwt.py',
    line: 8,
    severity: 'medium',
    type: 'protocol',
    oldValue: 'RS256 (RSA-PKCS1v15-SHA256)',
    newValue: 'ES256 (ECDSA-P256-SHA256)',
    details: 'JWT signing algorithm changed (both quantum-vulnerable)',
  },
  {
    id: 'diff-15',
    diffType: 'changed',
    component: 'AES mode',
    file: 'crypto/symmetric.py',
    line: 22,
    severity: 'info',
    type: 'algorithm',
    oldValue: 'AES-256-CBC',
    newValue: 'AES-256-GCM',
    details: 'Switched to authenticated encryption mode',
  },
];

export const MOCK_CBOM_DIFF: CBOMDiffData = {
  baseScan: MOCK_SCAN_SELECTORS[1]!, // scan-46
  targetScan: MOCK_SCAN_SELECTORS[0]!, // scan-47
  summary: {
    added: MOCK_DIFF_ITEMS.filter((i) => i.diffType === 'added').length,
    removed: MOCK_DIFF_ITEMS.filter((i) => i.diffType === 'removed').length,
    changed: MOCK_DIFF_ITEMS.filter((i) => i.diffType === 'changed').length,
    unchanged: 327,
  },
  items: MOCK_DIFF_ITEMS,
};

export function getCBOMDiff(
  _baseScanId?: string,
  _targetScanId?: string,
): CBOMDiffData {
  return MOCK_CBOM_DIFF;
}

export function getScanSelectors(): ScanSelector[] {
  return MOCK_SCAN_SELECTORS;
}
