/**
 * Mock data for the Asset Explorer — 50+ crypto assets across multiple repos/languages.
 */

export type AssetType = 'algorithm' | 'protocol' | 'key' | 'certificate';
export type QuantumAssetStatus = 'vulnerable' | 'safe' | 'broken' | 'unknown';
export type ComplianceTag = 'NIST 800-131A' | 'FIPS 140-3' | 'CNSA 2.0';

export interface CryptoAsset {
  id: string;
  name: string;
  type: AssetType;
  language: string;
  repository: string;
  repoId: string;
  file: string;
  line: number;
  quantumStatus: QuantumAssetStatus;
  compliance: ComplianceTag[];
}

export interface AssetSearchResult {
  assets: CryptoAsset[];
  total: number;
  page: number;
  pageSize: number;
}

export const MOCK_ASSETS: CryptoAsset[] = [
  // payment-service (repo-1) — Java, JS
  { id: 'a-001', name: 'AES-256-GCM', type: 'algorithm', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/crypto/Encryptor.java', line: 34, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-002', name: 'RSA-2048', type: 'algorithm', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/crypto/KeyGen.java', line: 89, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-003', name: 'SHA-256', type: 'algorithm', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/crypto/Hasher.java', line: 22, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3', 'CNSA 2.0'] },
  { id: 'a-004', name: 'MD5', type: 'algorithm', language: 'Python', repository: 'payment-service', repoId: 'repo-1', file: 'scripts/hash.py', line: 12, quantumStatus: 'broken', compliance: [] },
  { id: 'a-005', name: 'DES/ECB', type: 'algorithm', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/legacy/CryptoUtil.java', line: 67, quantumStatus: 'broken', compliance: [] },
  { id: 'a-006', name: 'TLS 1.3', type: 'protocol', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/network/SSLConfig.java', line: 15, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-007', name: 'X.509 Certificate', type: 'certificate', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/network/SSLConfig.java', line: 45, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-008', name: 'HMAC-SHA256', type: 'algorithm', language: 'JavaScript', repository: 'payment-service', repoId: 'repo-1', file: 'src/api/auth.js', line: 28, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-009', name: 'ECDSA-P256', type: 'algorithm', language: 'JavaScript', repository: 'payment-service', repoId: 'repo-1', file: 'src/api/sign.js', line: 41, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-010', name: 'RSA-4096', type: 'key', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/keys/RSAKeyStore.java', line: 55, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-011', name: 'SHA-1', type: 'algorithm', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/legacy/LegacyHash.java', line: 18, quantumStatus: 'broken', compliance: [] },
  { id: 'a-012', name: 'PBKDF2-SHA256', type: 'algorithm', language: 'Java', repository: 'payment-service', repoId: 'repo-1', file: 'src/main/auth/PasswordStore.java', line: 30, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },

  // auth-api (repo-2) — Python, JS
  { id: 'a-013', name: 'AES-256-GCM', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'crypto/encrypt.py', line: 15, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-014', name: 'RSA-2048', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'crypto/keygen.py', line: 42, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-015', name: 'Ed25519', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'auth/signing.py', line: 8, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-016', name: 'ECDH-P384', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'crypto/exchange.py', line: 19, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-017', name: 'SHA-512', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'auth/hash.py', line: 5, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3', 'CNSA 2.0'] },
  { id: 'a-018', name: 'TLS 1.2', type: 'protocol', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'network/client.py', line: 33, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-019', name: 'HMAC-SHA512', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'auth/token.py', line: 47, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-020', name: 'scrypt', type: 'algorithm', language: 'Python', repository: 'auth-api', repoId: 'repo-2', file: 'auth/password.py', line: 22, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },
  { id: 'a-021', name: 'ChaCha20-Poly1305', type: 'algorithm', language: 'JavaScript', repository: 'auth-api', repoId: 'repo-2', file: 'src/crypto/stream.js', line: 14, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },
  { id: 'a-022', name: 'ECDSA-P384', type: 'algorithm', language: 'JavaScript', repository: 'auth-api', repoId: 'repo-2', file: 'src/auth/jwt.js', line: 31, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },

  // data-pipeline (repo-3) — Python
  { id: 'a-023', name: 'AES-256-CBC', type: 'algorithm', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'pipeline/encrypt.py', line: 20, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-024', name: 'SHA-256', type: 'algorithm', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'pipeline/integrity.py', line: 9, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3', 'CNSA 2.0'] },
  { id: 'a-025', name: 'HMAC-SHA256', type: 'algorithm', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'pipeline/auth.py', line: 55, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-026', name: 'RSA-4096', type: 'key', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'keys/gen.py', line: 5, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-027', name: 'TLS 1.3', type: 'protocol', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'network/cfg.py', line: 10, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-028', name: 'PBKDF2-SHA256', type: 'algorithm', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'auth/password.py', line: 22, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-029', name: 'X.509 Certificate', type: 'certificate', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'certs/loader.py', line: 14, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },
  { id: 'a-030', name: 'Argon2id', type: 'algorithm', language: 'Python', repository: 'data-pipeline', repoId: 'repo-3', file: 'auth/kdf.py', line: 8, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },

  // mobile-backend (repo-4) — Java, Kotlin
  { id: 'a-031', name: 'AES-128-CBC', type: 'algorithm', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/crypto/LegacyAES.java', line: 40, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },
  { id: 'a-032', name: 'RSA-1024', type: 'algorithm', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/crypto/OldKeys.java', line: 22, quantumStatus: 'vulnerable', compliance: [] },
  { id: 'a-033', name: 'DES', type: 'algorithm', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/legacy/DESCipher.java', line: 15, quantumStatus: 'broken', compliance: [] },
  { id: 'a-034', name: 'MD5', type: 'algorithm', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/legacy/Hash.java', line: 8, quantumStatus: 'broken', compliance: [] },
  { id: 'a-035', name: 'SHA-1', type: 'algorithm', language: 'Kotlin', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/util/Digest.kt', line: 12, quantumStatus: 'broken', compliance: [] },
  { id: 'a-036', name: 'ECDSA-P256', type: 'algorithm', language: 'Kotlin', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/auth/Signer.kt', line: 28, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-037', name: 'AES-256-GCM', type: 'algorithm', language: 'Kotlin', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/crypto/AESEncrypt.kt', line: 19, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-038', name: 'TLS 1.0', type: 'protocol', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/network/LegacySSL.java', line: 50, quantumStatus: 'vulnerable', compliance: [] },
  { id: 'a-039', name: 'RC4', type: 'algorithm', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/legacy/StreamCipher.java', line: 33, quantumStatus: 'broken', compliance: [] },
  { id: 'a-040', name: 'ECDH-P256', type: 'algorithm', language: 'Kotlin', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/crypto/Exchange.kt', line: 44, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-041', name: 'X.509 Certificate', type: 'certificate', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/certs/TrustStore.java', line: 62, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-042', name: '3DES', type: 'algorithm', language: 'Java', repository: 'mobile-backend', repoId: 'repo-4', file: 'src/main/legacy/TripleDES.java', line: 25, quantumStatus: 'broken', compliance: [] },

  // api-gateway (repo-5) — Go
  { id: 'a-043', name: 'AES-256-GCM', type: 'algorithm', language: 'Go', repository: 'api-gateway', repoId: 'repo-5', file: 'internal/crypto/aes.go', line: 35, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-044', name: 'Ed25519', type: 'algorithm', language: 'Go', repository: 'api-gateway', repoId: 'repo-5', file: 'internal/auth/sign.go', line: 20, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-045', name: 'TLS 1.3', type: 'protocol', language: 'Go', repository: 'api-gateway', repoId: 'repo-5', file: 'internal/server/tls.go', line: 48, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-046', name: 'SHA-256', type: 'algorithm', language: 'Go', repository: 'api-gateway', repoId: 'repo-5', file: 'internal/hash/sha.go', line: 10, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3', 'CNSA 2.0'] },
  { id: 'a-047', name: 'ECDSA-P384', type: 'algorithm', language: 'Go', repository: 'api-gateway', repoId: 'repo-5', file: 'internal/auth/ecdsa.go', line: 25, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-048', name: 'RSA-2048', type: 'key', language: 'Go', repository: 'api-gateway', repoId: 'repo-5', file: 'internal/keys/rsa.go', line: 18, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },

  // user-service (repo-6) — TypeScript
  { id: 'a-049', name: 'bcrypt', type: 'algorithm', language: 'TypeScript', repository: 'user-service', repoId: 'repo-6', file: 'src/auth/password.ts', line: 11, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },
  { id: 'a-050', name: 'AES-256-GCM', type: 'algorithm', language: 'TypeScript', repository: 'user-service', repoId: 'repo-6', file: 'src/crypto/encrypt.ts', line: 24, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-051', name: 'RSA-2048', type: 'algorithm', language: 'TypeScript', repository: 'user-service', repoId: 'repo-6', file: 'src/auth/jwt.ts', line: 38, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },
  { id: 'a-052', name: 'HMAC-SHA256', type: 'algorithm', language: 'TypeScript', repository: 'user-service', repoId: 'repo-6', file: 'src/auth/token.ts', line: 15, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-053', name: 'TLS 1.3', type: 'protocol', language: 'TypeScript', repository: 'user-service', repoId: 'repo-6', file: 'src/server/config.ts', line: 42, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },

  // notification-svc (repo-7) — Python
  { id: 'a-054', name: 'AES-256-GCM', type: 'algorithm', language: 'Python', repository: 'notification-svc', repoId: 'repo-7', file: 'crypto/aes.py', line: 18, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-055', name: 'SHA-256', type: 'algorithm', language: 'Python', repository: 'notification-svc', repoId: 'repo-7', file: 'utils/hash.py', line: 7, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3', 'CNSA 2.0'] },
  { id: 'a-056', name: 'RSA-2048', type: 'key', language: 'Python', repository: 'notification-svc', repoId: 'repo-7', file: 'keys/rsa.py', line: 20, quantumStatus: 'vulnerable', compliance: ['NIST 800-131A'] },

  // config-service (repo-8) — Go
  { id: 'a-057', name: 'AES-256-GCM', type: 'algorithm', language: 'Go', repository: 'config-service', repoId: 'repo-8', file: 'internal/crypto/aes.go', line: 14, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3'] },
  { id: 'a-058', name: 'SHA-384', type: 'algorithm', language: 'Go', repository: 'config-service', repoId: 'repo-8', file: 'internal/hash/sha.go', line: 22, quantumStatus: 'safe', compliance: ['NIST 800-131A', 'FIPS 140-3', 'CNSA 2.0'] },
  { id: 'a-059', name: 'X.509 Certificate', type: 'certificate', language: 'Go', repository: 'config-service', repoId: 'repo-8', file: 'internal/certs/ca.go', line: 38, quantumStatus: 'safe', compliance: ['NIST 800-131A'] },
  { id: 'a-060', name: 'RSA-1024', type: 'algorithm', language: 'Go', repository: 'config-service', repoId: 'repo-8', file: 'internal/legacy/keys.go', line: 9, quantumStatus: 'vulnerable', compliance: [] },
];

export interface AssetFilters {
  search?: string;
  type?: AssetType;
  language?: string;
  quantumStatus?: QuantumAssetStatus;
  compliance?: ComplianceTag;
}

export function searchAssets(
  filters: AssetFilters,
  page: number,
  pageSize: number,
): AssetSearchResult {
  let filtered = [...MOCK_ASSETS];

  if (filters.search) {
    const q = filters.search.toLowerCase();
    filtered = filtered.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.repository.toLowerCase().includes(q) ||
        a.file.toLowerCase().includes(q) ||
        a.language.toLowerCase().includes(q),
    );
  }

  if (filters.type) {
    filtered = filtered.filter((a) => a.type === filters.type);
  }

  if (filters.language) {
    filtered = filtered.filter((a) => a.language === filters.language);
  }

  if (filters.quantumStatus) {
    filtered = filtered.filter((a) => a.quantumStatus === filters.quantumStatus);
  }

  if (filters.compliance) {
    filtered = filtered.filter((a) => a.compliance.includes(filters.compliance!));
  }

  const total = filtered.length;
  const start = (page - 1) * pageSize;
  const assets = filtered.slice(start, start + pageSize);

  return { assets, total, page, pageSize };
}
