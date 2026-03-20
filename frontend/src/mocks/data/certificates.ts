/**
 * Mock data for the Certificate Expiry Calendar view.
 */

export interface Certificate {
  id: string;
  commonName: string;
  issuer: string;
  algorithm: string;
  keySize: number;
  repository: string;
  file: string;
  expiryDate: string; // ISO date string
  issuedDate: string; // ISO date string
  serialNumber: string;
  quantumStatus: 'safe' | 'vulnerable' | 'broken' | 'unknown';
}

/**
 * Generate a date relative to today.
 */
function daysFromNow(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().split('T')[0]!;
}

export const MOCK_CERTIFICATES: Certificate[] = [
  {
    id: 'cert-cal-1',
    commonName: 'api.payment.internal',
    issuer: 'Internal CA',
    algorithm: 'RSA',
    keySize: 2048,
    repository: 'payment-service',
    file: 'certs/api.pem',
    expiryDate: daysFromNow(-5),
    issuedDate: daysFromNow(-370),
    serialNumber: 'A1:B2:C3:D4:E5:F6:01',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-2',
    commonName: 'auth.internal',
    issuer: 'Internal CA',
    algorithm: 'ECDSA',
    keySize: 256,
    repository: 'auth-api',
    file: 'certs/auth.pem',
    expiryDate: daysFromNow(3),
    issuedDate: daysFromNow(-362),
    serialNumber: 'A1:B2:C3:D4:E5:F6:02',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-3',
    commonName: '*.svc.cluster.local',
    issuer: 'Istio CA',
    algorithm: 'ECDSA',
    keySize: 384,
    repository: 'data-pipeline',
    file: 'k8s/tls-secret.yaml',
    expiryDate: daysFromNow(12),
    issuedDate: daysFromNow(-353),
    serialNumber: 'A1:B2:C3:D4:E5:F6:03',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-4',
    commonName: 'mobile.api.example.com',
    issuer: "Let's Encrypt R3",
    algorithm: 'RSA',
    keySize: 2048,
    repository: 'mobile-backend',
    file: 'certs/mobile.pem',
    expiryDate: daysFromNow(25),
    issuedDate: daysFromNow(-65),
    serialNumber: 'A1:B2:C3:D4:E5:F6:04',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-5',
    commonName: 'grpc.payment.internal',
    issuer: 'Internal CA',
    algorithm: 'RSA',
    keySize: 4096,
    repository: 'payment-service',
    file: 'certs/grpc.pem',
    expiryDate: daysFromNow(45),
    issuedDate: daysFromNow(-320),
    serialNumber: 'A1:B2:C3:D4:E5:F6:05',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-6',
    commonName: 'Root CA',
    issuer: 'Self-signed',
    algorithm: 'RSA',
    keySize: 4096,
    repository: 'payment-service',
    file: 'certs/root-ca.pem',
    expiryDate: daysFromNow(180),
    issuedDate: daysFromNow(-1825),
    serialNumber: 'A1:B2:C3:D4:E5:F6:06',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-7',
    commonName: 'Intermediate CA',
    issuer: 'Root CA',
    algorithm: 'RSA',
    keySize: 4096,
    repository: 'payment-service',
    file: 'certs/intermediate-ca.pem',
    expiryDate: daysFromNow(92),
    issuedDate: daysFromNow(-273),
    serialNumber: 'A1:B2:C3:D4:E5:F6:07',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-8',
    commonName: 'webhook.example.com',
    issuer: "Let's Encrypt R3",
    algorithm: 'ECDSA',
    keySize: 256,
    repository: 'auth-api',
    file: 'certs/webhook.pem',
    expiryDate: daysFromNow(60),
    issuedDate: daysFromNow(-30),
    serialNumber: 'A1:B2:C3:D4:E5:F6:08',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-9',
    commonName: 'dev.self-signed',
    issuer: 'Self-signed',
    algorithm: 'RSA',
    keySize: 2048,
    repository: 'mobile-backend',
    file: 'dev/dev.pem',
    expiryDate: daysFromNow(-30),
    issuedDate: daysFromNow(-395),
    serialNumber: 'A1:B2:C3:D4:E5:F6:09',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-10',
    commonName: 'staging.example.com',
    issuer: "Let's Encrypt R3",
    algorithm: 'RSA',
    keySize: 2048,
    repository: 'data-pipeline',
    file: 'certs/staging.pem',
    expiryDate: daysFromNow(120),
    issuedDate: daysFromNow(-245),
    serialNumber: 'A1:B2:C3:D4:E5:F6:10',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-11',
    commonName: 'kafka.internal',
    issuer: 'Internal CA',
    algorithm: 'RSA',
    keySize: 2048,
    repository: 'data-pipeline',
    file: 'certs/kafka.pem',
    expiryDate: daysFromNow(5),
    issuedDate: daysFromNow(-360),
    serialNumber: 'A1:B2:C3:D4:E5:F6:11',
    quantumStatus: 'vulnerable',
  },
  {
    id: 'cert-cal-12',
    commonName: 'redis.internal',
    issuer: 'Internal CA',
    algorithm: 'ECDSA',
    keySize: 256,
    repository: 'auth-api',
    file: 'certs/redis.pem',
    expiryDate: daysFromNow(200),
    issuedDate: daysFromNow(-165),
    serialNumber: 'A1:B2:C3:D4:E5:F6:12',
    quantumStatus: 'vulnerable',
  },
];

export function getCertificates(): Certificate[] {
  return MOCK_CERTIFICATES;
}
