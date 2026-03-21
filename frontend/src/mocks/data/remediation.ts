export type RemediationConfidence = 'high' | 'medium' | 'low';
export type RemediationProvider = 'anthropic' | 'openai' | 'ollama';

export interface RemediationDiff {
  originalCode: string;
  fixedCode: string;
}

export interface Remediation {
  id: string;
  findingId: string;
  confidence: RemediationConfidence;
  provider: RemediationProvider;
  explanation: string;
  diff: RemediationDiff;
  createdAt: string;
}

export const MOCK_REMEDIATIONS: Remediation[] = [
  {
    id: 'rem-001',
    findingId: 'f-002',
    confidence: 'high',
    provider: 'anthropic',
    explanation:
      'MD5 is cryptographically broken and must not be used for any security purpose. This fix replaces hashlib.md5() with hashlib.sha256(), which provides collision resistance suitable for current security requirements. SHA-256 is approved by NIST SP 800-131A and is quantum-safe for symmetric hashing.',
    diff: {
      originalCode: [
        'import hashlib',
        '',
        'digest = hashlib.md5(data).hexdigest()',
        'return digest',
      ].join('\n'),
      fixedCode: [
        'import hashlib',
        '',
        'digest = hashlib.sha256(data).hexdigest()',
        'return digest',
      ].join('\n'),
    },
    createdAt: '2026-03-20T14:30:00Z',
  },
  {
    id: 'rem-002',
    findingId: 'f-003',
    confidence: 'high',
    provider: 'anthropic',
    explanation:
      'DES with ECB mode is doubly insecure: DES has a 56-bit key (brute-forceable) and ECB mode leaks plaintext patterns. This fix migrates to AES-256 with GCM mode, providing authenticated encryption with a 256-bit key. GCM mode prevents both pattern leakage and ciphertext tampering.',
    diff: {
      originalCode: [
        '// Legacy encryption',
        'private static final String ALGO = "DES/ECB/PKCS5Padding";',
        'Cipher cipher = Cipher.getInstance(ALGO);',
        'cipher.init(Cipher.ENCRYPT_MODE, secretKey);',
      ].join('\n'),
      fixedCode: [
        '// Modern authenticated encryption',
        'private static final String ALGO = "AES/GCM/NoPadding";',
        'Cipher cipher = Cipher.getInstance(ALGO);',
        'GCMParameterSpec spec = new GCMParameterSpec(128, iv);',
        'cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);',
      ].join('\n'),
    },
    createdAt: '2026-03-20T14:35:00Z',
  },
  {
    id: 'rem-003',
    findingId: 'f-004',
    confidence: 'medium',
    provider: 'openai',
    explanation:
      'SHA-1 has been deprecated for digital signatures since 2011 (NIST SP 800-131A). Known collision attacks make it unsuitable for signature verification. This fix replaces SHA-1 with SHA-256 for HMAC-based signature verification.',
    diff: {
      originalCode: [
        'def verify_signature(data, sig):',
        '    h = hashlib.new("sha1")',
        '    h.update(data)',
        '    return hmac.compare_digest(h.hexdigest(), sig)',
      ].join('\n'),
      fixedCode: [
        'def verify_signature(data, sig):',
        '    h = hashlib.new("sha256")',
        '    h.update(data)',
        '    return hmac.compare_digest(h.hexdigest(), sig)',
      ].join('\n'),
    },
    createdAt: '2026-03-21T09:15:00Z',
  },
  {
    id: 'rem-004',
    findingId: 'f-006',
    confidence: 'low',
    provider: 'ollama',
    explanation:
      'RSA-2048 is vulnerable to quantum attacks via Shor\'s algorithm. For post-quantum safety, consider ML-KEM (Kyber) for key encapsulation. This fix shows a hybrid approach using both RSA-4096 (interim) and a comment noting the planned ML-KEM migration path.',
    diff: {
      originalCode: [
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
        '// 2048-bit key — quantum vulnerable',
        'kpg.initialize(2048);',
        'KeyPair kp = kpg.generateKeyPair();',
      ].join('\n'),
      fixedCode: [
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
        '// 4096-bit key — interim measure pending ML-KEM migration',
        'kpg.initialize(4096);',
        'KeyPair kp = kpg.generateKeyPair();',
        '// TODO: migrate to ML-KEM (Kyber) for post-quantum safety',
      ].join('\n'),
    },
    createdAt: '2026-03-22T11:00:00Z',
  },
];

export function getRemediationForFinding(findingId: string): Remediation | undefined {
  return MOCK_REMEDIATIONS.find((r) => r.findingId === findingId);
}
