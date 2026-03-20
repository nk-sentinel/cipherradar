/**
 * Mock data for the D3.js Dependency Graph view.
 * 100+ nodes with relationships between crypto assets.
 */

export type NodeType = 'algorithm' | 'protocol' | 'library' | 'certificate' | 'key';
export type QuantumNodeStatus = 'safe' | 'vulnerable' | 'broken' | 'unknown';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  language: string;
  quantumStatus: QuantumNodeStatus;
  severity: SeverityLevel;
  repository: string;
  file: string;
  line: number;
}

export interface GraphLink {
  source: string;
  target: string;
  relationship: 'uses' | 'implements' | 'wraps' | 'depends-on' | 'configures';
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const LIBRARIES: GraphNode[] = [
  { id: 'lib-1', label: 'javax.crypto', type: 'library', language: 'Java', quantumStatus: 'unknown', severity: 'info', repository: 'payment-service', file: 'pom.xml', line: 45 },
  { id: 'lib-2', label: 'Bouncy Castle', type: 'library', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'pom.xml', line: 52 },
  { id: 'lib-3', label: 'cryptography (Python)', type: 'library', language: 'Python', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'requirements.txt', line: 8 },
  { id: 'lib-4', label: 'node:crypto', type: 'library', language: 'JavaScript', quantumStatus: 'unknown', severity: 'info', repository: 'payment-service', file: 'package.json', line: 1 },
  { id: 'lib-5', label: 'hashlib', type: 'library', language: 'Python', quantumStatus: 'unknown', severity: 'info', repository: 'data-pipeline', file: 'requirements.txt', line: 1 },
  { id: 'lib-6', label: 'OpenSSL', type: 'library', language: 'Python', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'requirements.txt', line: 3 },
  { id: 'lib-7', label: 'jose (JWT)', type: 'library', language: 'JavaScript', quantumStatus: 'vulnerable', severity: 'medium', repository: 'auth-api', file: 'package.json', line: 12 },
  { id: 'lib-8', label: 'pycryptodome', type: 'library', language: 'Python', quantumStatus: 'unknown', severity: 'info', repository: 'mobile-backend', file: 'requirements.txt', line: 5 },
  { id: 'lib-9', label: 'kotlinx.crypto', type: 'library', language: 'Kotlin', quantumStatus: 'unknown', severity: 'info', repository: 'mobile-backend', file: 'build.gradle.kts', line: 22 },
  { id: 'lib-10', label: 'tink', type: 'library', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'pom.xml', line: 60 },
];

const ALGORITHMS: GraphNode[] = [
  { id: 'alg-1', label: 'AES-256-GCM', type: 'algorithm', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'CryptoService.java', line: 34 },
  { id: 'alg-2', label: 'AES-128-CBC', type: 'algorithm', language: 'Python', quantumStatus: 'safe', severity: 'low', repository: 'auth-api', file: 'encryption.py', line: 12 },
  { id: 'alg-3', label: 'RSA-2048', type: 'algorithm', language: 'Java', quantumStatus: 'vulnerable', severity: 'medium', repository: 'payment-service', file: 'KeyGen.java', line: 89 },
  { id: 'alg-4', label: 'RSA-4096', type: 'algorithm', language: 'Python', quantumStatus: 'vulnerable', severity: 'low', repository: 'auth-api', file: 'keys.py', line: 22 },
  { id: 'alg-5', label: 'ECDSA-P256', type: 'algorithm', language: 'JavaScript', quantumStatus: 'vulnerable', severity: 'medium', repository: 'payment-service', file: 'sign.js', line: 15 },
  { id: 'alg-6', label: 'ECDH-P384', type: 'algorithm', language: 'Java', quantumStatus: 'vulnerable', severity: 'medium', repository: 'payment-service', file: 'KeyExchange.java', line: 44 },
  { id: 'alg-7', label: 'SHA-256', type: 'algorithm', language: 'Python', quantumStatus: 'safe', severity: 'info', repository: 'data-pipeline', file: 'hash.py', line: 8 },
  { id: 'alg-8', label: 'SHA-512', type: 'algorithm', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'Digest.java', line: 20 },
  { id: 'alg-9', label: 'MD5', type: 'algorithm', language: 'Python', quantumStatus: 'broken', severity: 'high', repository: 'auth-api', file: 'legacy_hash.py', line: 5 },
  { id: 'alg-10', label: 'SHA-1', type: 'algorithm', language: 'Java', quantumStatus: 'broken', severity: 'high', repository: 'mobile-backend', file: 'Hash.java', line: 33 },
  { id: 'alg-11', label: 'DES', type: 'algorithm', language: 'Java', quantumStatus: 'broken', severity: 'critical', repository: 'payment-service', file: 'CryptoUtil.java', line: 67 },
  { id: 'alg-12', label: '3DES', type: 'algorithm', language: 'Java', quantumStatus: 'broken', severity: 'high', repository: 'mobile-backend', file: 'Legacy.java', line: 12 },
  { id: 'alg-13', label: 'HMAC-SHA256', type: 'algorithm', language: 'JavaScript', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'auth.js', line: 45 },
  { id: 'alg-14', label: 'PBKDF2-SHA256', type: 'algorithm', language: 'Python', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'password.py', line: 22 },
  { id: 'alg-15', label: 'Argon2id', type: 'algorithm', language: 'Python', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'password_v2.py', line: 8 },
  { id: 'alg-16', label: 'ChaCha20-Poly1305', type: 'algorithm', language: 'Go', quantumStatus: 'safe', severity: 'info', repository: 'data-pipeline', file: 'encrypt.go', line: 30 },
  { id: 'alg-17', label: 'Ed25519', type: 'algorithm', language: 'Python', quantumStatus: 'vulnerable', severity: 'medium', repository: 'auth-api', file: 'signing.py', line: 11 },
  { id: 'alg-18', label: 'X25519', type: 'algorithm', language: 'JavaScript', quantumStatus: 'vulnerable', severity: 'medium', repository: 'payment-service', file: 'kex.js', line: 8 },
  { id: 'alg-19', label: 'RC4', type: 'algorithm', language: 'Java', quantumStatus: 'broken', severity: 'critical', repository: 'mobile-backend', file: 'StreamCipher.java', line: 15 },
  { id: 'alg-20', label: 'Blowfish', type: 'algorithm', language: 'Python', quantumStatus: 'broken', severity: 'high', repository: 'mobile-backend', file: 'legacy_enc.py', line: 25 },
  { id: 'alg-21', label: 'AES-256-CTR', type: 'algorithm', language: 'JavaScript', quantumStatus: 'safe', severity: 'info', repository: 'data-pipeline', file: 'stream_enc.js', line: 18 },
  { id: 'alg-22', label: 'RSA-1024', type: 'algorithm', language: 'Java', quantumStatus: 'vulnerable', severity: 'critical', repository: 'mobile-backend', file: 'OldKeys.java', line: 9 },
  { id: 'alg-23', label: 'DSA-1024', type: 'algorithm', language: 'Java', quantumStatus: 'vulnerable', severity: 'high', repository: 'mobile-backend', file: 'Signer.java', line: 42 },
  { id: 'alg-24', label: 'ECDSA-P384', type: 'algorithm', language: 'Python', quantumStatus: 'vulnerable', severity: 'medium', repository: 'data-pipeline', file: 'verify.py', line: 30 },
  { id: 'alg-25', label: 'Scrypt', type: 'algorithm', language: 'JavaScript', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'kdf.js', line: 5 },
];

const PROTOCOLS: GraphNode[] = [
  { id: 'proto-1', label: 'TLS 1.3', type: 'protocol', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'SSLConfig.java', line: 20 },
  { id: 'proto-2', label: 'TLS 1.2', type: 'protocol', language: 'Python', quantumStatus: 'safe', severity: 'low', repository: 'auth-api', file: 'tls_config.py', line: 14 },
  { id: 'proto-3', label: 'TLS 1.0', type: 'protocol', language: 'Java', quantumStatus: 'vulnerable', severity: 'critical', repository: 'mobile-backend', file: 'NetConfig.java', line: 8 },
  { id: 'proto-4', label: 'SSH 2.0', type: 'protocol', language: 'Python', quantumStatus: 'safe', severity: 'info', repository: 'data-pipeline', file: 'deploy.py', line: 45 },
  { id: 'proto-5', label: 'mTLS', type: 'protocol', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'GrpcConfig.java', line: 30 },
  { id: 'proto-6', label: 'HTTPS', type: 'protocol', language: 'JavaScript', quantumStatus: 'safe', severity: 'info', repository: 'auth-api', file: 'server.js', line: 22 },
  { id: 'proto-7', label: 'JWT (RS256)', type: 'protocol', language: 'JavaScript', quantumStatus: 'vulnerable', severity: 'medium', repository: 'auth-api', file: 'jwt.js', line: 10 },
  { id: 'proto-8', label: 'JWT (ES256)', type: 'protocol', language: 'Python', quantumStatus: 'vulnerable', severity: 'medium', repository: 'auth-api', file: 'tokens.py', line: 35 },
  { id: 'proto-9', label: 'DTLS 1.2', type: 'protocol', language: 'Kotlin', quantumStatus: 'safe', severity: 'info', repository: 'mobile-backend', file: 'UdpClient.kt', line: 18 },
  { id: 'proto-10', label: 'SSL 3.0', type: 'protocol', language: 'Java', quantumStatus: 'broken', severity: 'critical', repository: 'mobile-backend', file: 'LegacySSL.java', line: 5 },
];

const CERTIFICATES: GraphNode[] = [
  { id: 'cert-1', label: 'api.example.com (RSA)', type: 'certificate', language: 'Java', quantumStatus: 'vulnerable', severity: 'medium', repository: 'payment-service', file: 'truststore.jks', line: 1 },
  { id: 'cert-2', label: 'auth.internal (ECDSA)', type: 'certificate', language: 'Python', quantumStatus: 'vulnerable', severity: 'medium', repository: 'auth-api', file: 'certs/auth.pem', line: 1 },
  { id: 'cert-3', label: 'Root CA (RSA-4096)', type: 'certificate', language: 'Java', quantumStatus: 'vulnerable', severity: 'low', repository: 'payment-service', file: 'ca-bundle.crt', line: 1 },
  { id: 'cert-4', label: 'Self-signed (RSA-2048)', type: 'certificate', language: 'Python', quantumStatus: 'vulnerable', severity: 'high', repository: 'mobile-backend', file: 'dev.pem', line: 1 },
  { id: 'cert-5', label: 'Wildcard *.svc.local', type: 'certificate', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'data-pipeline', file: 'svc.crt', line: 1 },
];

const KEYS: GraphNode[] = [
  { id: 'key-1', label: 'ENCRYPTION_KEY (hardcoded)', type: 'key', language: 'Python', quantumStatus: 'unknown', severity: 'critical', repository: 'payment-service', file: '.env', line: 5 },
  { id: 'key-2', label: 'JWT signing key', type: 'key', language: 'JavaScript', quantumStatus: 'vulnerable', severity: 'high', repository: 'auth-api', file: 'config.js', line: 12 },
  { id: 'key-3', label: 'AES-256 session key', type: 'key', language: 'Java', quantumStatus: 'safe', severity: 'info', repository: 'payment-service', file: 'SessionManager.java', line: 56 },
  { id: 'key-4', label: 'RSA private key', type: 'key', language: 'Java', quantumStatus: 'vulnerable', severity: 'medium', repository: 'payment-service', file: 'keys/private.pem', line: 1 },
  { id: 'key-5', label: 'HMAC secret', type: 'key', language: 'Python', quantumStatus: 'safe', severity: 'low', repository: 'data-pipeline', file: 'secrets.py', line: 3 },
];

// Additional algorithm nodes to push us past 100
const EXTRA_ALGORITHMS: GraphNode[] = Array.from({ length: 60 }, (_, i) => {
  const langs = ['Java', 'Python', 'JavaScript', 'Kotlin', 'Go', 'TypeScript'];
  const repos = ['payment-service', 'auth-api', 'data-pipeline', 'mobile-backend'];
  const algNames = ['AES-256-GCM', 'RSA-2048', 'SHA-256', 'ECDSA-P256', 'HMAC-SHA256', 'PBKDF2', 'Ed25519', 'ChaCha20', 'AES-128-CBC', 'SHA-512'];
  const statuses: QuantumNodeStatus[] = ['safe', 'vulnerable', 'broken', 'unknown'];
  const sevs: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];

  return {
    id: `extra-${String(i + 1)}`,
    label: `${algNames[i % algNames.length]!}#${String(i + 1)}`,
    type: 'algorithm' as NodeType,
    language: langs[i % langs.length]!,
    quantumStatus: statuses[i % statuses.length]!,
    severity: sevs[Math.min(i % sevs.length, sevs.length - 1)]!,
    repository: repos[i % repos.length]!,
    file: `src/crypto/module_${String(i + 1)}.${langs[i % langs.length]! === 'Java' ? 'java' : langs[i % langs.length]! === 'Python' ? 'py' : 'js'}`,
    line: 10 + i * 5,
  };
});

const ALL_NODES: GraphNode[] = [
  ...LIBRARIES,
  ...ALGORITHMS,
  ...PROTOCOLS,
  ...CERTIFICATES,
  ...KEYS,
  ...EXTRA_ALGORITHMS,
];

const BASE_LINKS: GraphLink[] = [
  // Libraries -> Algorithms
  { source: 'lib-1', target: 'alg-1', relationship: 'implements' },
  { source: 'lib-1', target: 'alg-3', relationship: 'implements' },
  { source: 'lib-1', target: 'alg-6', relationship: 'implements' },
  { source: 'lib-1', target: 'alg-8', relationship: 'implements' },
  { source: 'lib-1', target: 'alg-11', relationship: 'implements' },
  { source: 'lib-2', target: 'alg-1', relationship: 'implements' },
  { source: 'lib-2', target: 'alg-5', relationship: 'implements' },
  { source: 'lib-2', target: 'alg-12', relationship: 'implements' },
  { source: 'lib-3', target: 'alg-2', relationship: 'implements' },
  { source: 'lib-3', target: 'alg-4', relationship: 'implements' },
  { source: 'lib-3', target: 'alg-14', relationship: 'implements' },
  { source: 'lib-3', target: 'alg-15', relationship: 'implements' },
  { source: 'lib-3', target: 'alg-17', relationship: 'implements' },
  { source: 'lib-4', target: 'alg-5', relationship: 'implements' },
  { source: 'lib-4', target: 'alg-13', relationship: 'implements' },
  { source: 'lib-4', target: 'alg-18', relationship: 'implements' },
  { source: 'lib-4', target: 'alg-21', relationship: 'implements' },
  { source: 'lib-5', target: 'alg-7', relationship: 'implements' },
  { source: 'lib-5', target: 'alg-9', relationship: 'implements' },
  { source: 'lib-6', target: 'proto-2', relationship: 'implements' },
  { source: 'lib-6', target: 'alg-4', relationship: 'implements' },
  { source: 'lib-7', target: 'proto-7', relationship: 'implements' },
  { source: 'lib-7', target: 'proto-8', relationship: 'implements' },
  { source: 'lib-8', target: 'alg-20', relationship: 'implements' },
  { source: 'lib-8', target: 'alg-2', relationship: 'implements' },
  { source: 'lib-9', target: 'alg-10', relationship: 'implements' },
  { source: 'lib-10', target: 'alg-1', relationship: 'wraps' },
  { source: 'lib-10', target: 'alg-16', relationship: 'wraps' },

  // Algorithms -> Protocols
  { source: 'alg-1', target: 'proto-1', relationship: 'uses' },
  { source: 'alg-3', target: 'proto-7', relationship: 'uses' },
  { source: 'alg-5', target: 'proto-8', relationship: 'uses' },
  { source: 'alg-6', target: 'proto-1', relationship: 'uses' },
  { source: 'alg-8', target: 'proto-1', relationship: 'uses' },
  { source: 'alg-13', target: 'proto-7', relationship: 'uses' },
  { source: 'alg-11', target: 'proto-3', relationship: 'uses' },
  { source: 'alg-19', target: 'proto-10', relationship: 'uses' },
  { source: 'alg-17', target: 'proto-4', relationship: 'uses' },
  { source: 'alg-18', target: 'proto-6', relationship: 'uses' },

  // Protocols -> Certificates
  { source: 'proto-1', target: 'cert-1', relationship: 'configures' },
  { source: 'proto-1', target: 'cert-3', relationship: 'configures' },
  { source: 'proto-2', target: 'cert-2', relationship: 'configures' },
  { source: 'proto-5', target: 'cert-1', relationship: 'configures' },
  { source: 'proto-5', target: 'cert-5', relationship: 'configures' },
  { source: 'proto-3', target: 'cert-4', relationship: 'configures' },

  // Keys -> Algorithms
  { source: 'key-1', target: 'alg-1', relationship: 'uses' },
  { source: 'key-2', target: 'alg-3', relationship: 'uses' },
  { source: 'key-3', target: 'alg-1', relationship: 'uses' },
  { source: 'key-4', target: 'alg-3', relationship: 'uses' },
  { source: 'key-5', target: 'alg-13', relationship: 'uses' },

  // Cross-protocol dependencies
  { source: 'proto-6', target: 'proto-2', relationship: 'depends-on' },
  { source: 'proto-5', target: 'proto-1', relationship: 'depends-on' },
  { source: 'proto-9', target: 'alg-1', relationship: 'uses' },
];

// Generate some links for extra nodes
const EXTRA_LINKS: GraphLink[] = EXTRA_ALGORITHMS.map((node, i) => ({
  source: LIBRARIES[i % LIBRARIES.length]!.id,
  target: node.id,
  relationship: 'implements' as const,
}));

const ALL_LINKS: GraphLink[] = [...BASE_LINKS, ...EXTRA_LINKS];

export const MOCK_GRAPH_DATA: GraphData = {
  nodes: ALL_NODES,
  links: ALL_LINKS,
};

export function getGraphData(): GraphData {
  return MOCK_GRAPH_DATA;
}
