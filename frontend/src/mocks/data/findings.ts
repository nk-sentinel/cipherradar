export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type QuantumStatus = 'vulnerable' | 'safe' | 'broken' | 'unknown';
export type DetectionPass = 1 | 2 | 3;

export interface CodeSnippet {
  startLine: number;
  highlightLines: number[];
  lines: string[];
}

export interface Finding {
  id: string;
  repoId: string;
  severity: Severity;
  file: string;
  line: number;
  title: string;
  algorithm: string | null;
  quantumStatus: QuantumStatus;
  pass: DetectionPass;
  ruleId: string;
  confidence: 'high' | 'medium' | 'low';
  assetType: string;
  code: CodeSnippet;
  remediation: string;
}

export const MOCK_FINDINGS: Finding[] = [
  {
    id: 'f-001',
    repoId: 'repo-1',
    severity: 'critical',
    file: 'SSLConfig.java',
    line: 45,
    title: 'Certificate validation disabled',
    algorithm: null,
    quantumStatus: 'vulnerable',
    pass: 1,
    ruleId: 'cbom-java-trust-all-certificates',
    confidence: 'high',
    assetType: 'Certificate',
    code: {
      startLine: 43,
      highlightLines: [45, 46],
      lines: [
        'TrustManager[] trustAll = new TrustManager[] {',
        '    new X509TrustManager() {',
        '        public void checkClientTrusted(...) { }',
        '        public void checkServerTrusted(...) { }',
        '    }',
        '};',
      ],
    },
    remediation:
      'Remove custom TrustManager. Use system default or configure a truststore with your CA certificates.',
  },
  {
    id: 'f-002',
    repoId: 'repo-1',
    severity: 'high',
    file: 'hash.py',
    line: 12,
    title: 'MD5 hash function',
    algorithm: 'MD5',
    quantumStatus: 'broken',
    pass: 1,
    ruleId: 'cbom-python-md5-usage',
    confidence: 'high',
    assetType: 'Hash',
    code: {
      startLine: 10,
      highlightLines: [12],
      lines: [
        'import hashlib',
        '',
        'digest = hashlib.md5(data).hexdigest()',
        'return digest',
      ],
    },
    remediation:
      'Replace MD5 with SHA-256 or SHA-3. MD5 is cryptographically broken and unsuitable for security purposes.',
  },
  {
    id: 'f-003',
    repoId: 'repo-1',
    severity: 'high',
    file: 'CryptoUtil.java',
    line: 67,
    title: 'DES/ECB — broken cipher',
    algorithm: 'DES',
    quantumStatus: 'broken',
    pass: 1,
    ruleId: 'cbom-java-des-ecb',
    confidence: 'high',
    assetType: 'Cipher',
    code: {
      startLine: 65,
      highlightLines: [67],
      lines: [
        '// Legacy encryption',
        'private static final String ALGO = "DES/ECB/PKCS5Padding";',
        'Cipher cipher = Cipher.getInstance(ALGO);',
        'cipher.init(Cipher.ENCRYPT_MODE, secretKey);',
      ],
    },
    remediation:
      'Replace DES with AES-256-GCM. DES has a 56-bit key and is broken. ECB mode leaks patterns.',
  },
  {
    id: 'f-004',
    repoId: 'repo-1',
    severity: 'high',
    file: 'auth/verify.py',
    line: 23,
    title: 'SHA-1 signature verification',
    algorithm: 'SHA-1',
    quantumStatus: 'broken',
    pass: 1,
    ruleId: 'cbom-python-sha1-signature',
    confidence: 'high',
    assetType: 'Hash',
    code: {
      startLine: 21,
      highlightLines: [23],
      lines: [
        'def verify_signature(data, sig):',
        '    h = hashlib.new("sha1")',
        '    h.update(data)',
        '    return hmac.compare_digest(h.hexdigest(), sig)',
      ],
    },
    remediation:
      'Migrate from SHA-1 to SHA-256 or SHA-3. SHA-1 is deprecated for digital signatures per NIST SP 800-131A.',
  },
  {
    id: 'f-005',
    repoId: 'repo-1',
    severity: 'high',
    file: '.env',
    line: 5,
    title: 'Hardcoded ENCRYPTION_KEY',
    algorithm: null,
    quantumStatus: 'unknown',
    pass: 1,
    ruleId: 'cbom-generic-hardcoded-key',
    confidence: 'medium',
    assetType: 'Key Material',
    code: {
      startLine: 3,
      highlightLines: [5],
      lines: [
        'DATABASE_URL=postgres://...',
        'API_SECRET=changeme',
        'ENCRYPTION_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        'LOG_LEVEL=info',
      ],
    },
    remediation:
      'Move encryption keys to a secrets manager (AWS Secrets Manager, Vault). Never hardcode key material in source.',
  },
  {
    id: 'f-006',
    repoId: 'repo-1',
    severity: 'medium',
    file: 'KeyGen.java',
    line: 89,
    title: 'RSA-2048 key generation',
    algorithm: 'RSA',
    quantumStatus: 'vulnerable',
    pass: 1,
    ruleId: 'cbom-java-rsa-keygen',
    confidence: 'high',
    assetType: 'Key Generation',
    code: {
      startLine: 87,
      highlightLines: [89],
      lines: [
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
        '// 2048-bit key — quantum vulnerable',
        'kpg.initialize(2048);',
        'KeyPair kp = kpg.generateKeyPair();',
      ],
    },
    remediation:
      'Consider migrating to ML-KEM (Kyber) for key encapsulation or increase RSA key size to 4096 as an interim measure.',
  },
  {
    id: 'f-007',
    repoId: 'repo-1',
    severity: 'medium',
    file: 'network/tls_client.py',
    line: 18,
    title: 'CERT_NONE — SSL verification disabled',
    algorithm: null,
    quantumStatus: 'vulnerable',
    pass: 2,
    ruleId: 'cbom-python-cert-none',
    confidence: 'high',
    assetType: 'Certificate',
    code: {
      startLine: 16,
      highlightLines: [18],
      lines: [
        'import ssl',
        'ctx = ssl.create_default_context()',
        'ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE',
        'conn = ctx.wrap_socket(sock, server_hostname=host)',
      ],
    },
    remediation:
      'Remove CERT_NONE. Use ssl.CERT_REQUIRED with proper CA bundle to validate server certificates.',
  },
  {
    id: 'f-008',
    repoId: 'repo-1',
    severity: 'info',
    file: 'aes.py',
    line: 15,
    title: 'AES-256-GCM encryption',
    algorithm: 'AES',
    quantumStatus: 'safe',
    pass: 1,
    ruleId: 'cbom-python-aes-gcm',
    confidence: 'high',
    assetType: 'Cipher',
    code: {
      startLine: 13,
      highlightLines: [15],
      lines: [
        'from cryptography.hazmat.primitives.ciphers.aead import AESGCM',
        'key = AESGCM.generate_key(bit_length=256)',
        'aesgcm = AESGCM(key)',
        'ct = aesgcm.encrypt(nonce, plaintext, aad)',
      ],
    },
    remediation:
      'No action required. AES-256-GCM is a strong authenticated encryption algorithm considered quantum-safe for symmetric use.',
  },
];

export function getFindingsForRepo(repoId: string): Finding[] {
  return MOCK_FINDINGS.filter((f) => f.repoId === repoId);
}

export function getFindingById(findingId: string): Finding | undefined {
  return MOCK_FINDINGS.find((f) => f.id === findingId);
}
