export interface RuntimeObservation {
  id: string;
  serviceName: string;
  observedTlsVersion: string;
  configuredTlsVersion: string;
  observedCipherSuite: string;
  timestamp: string;
  mismatch: boolean;
}

export interface RuntimeSummary {
  projectId: string;
  observations: RuntimeObservation[];
  tlsVersionChart: TlsVersionChartItem[];
}

export interface TlsVersionChartItem {
  version: string;
  configured: number;
  observed: number;
}

export interface EnrichedFinding {
  findingId: string;
  file: string;
  title: string;
  staticTls: string;
  runtimeTls: string;
  mismatch: boolean;
  lastSeen: string;
}

export const MOCK_RUNTIME_SUMMARY: RuntimeSummary = {
  projectId: 'repo-1',
  observations: [
    {
      id: 'rt-001',
      serviceName: 'api-gateway',
      observedTlsVersion: 'TLS 1.3',
      configuredTlsVersion: 'TLS 1.3',
      observedCipherSuite: 'TLS_AES_256_GCM_SHA384',
      timestamp: '2026-03-22T10:15:00Z',
      mismatch: false,
    },
    {
      id: 'rt-002',
      serviceName: 'payment-service',
      observedTlsVersion: 'TLS 1.0',
      configuredTlsVersion: 'TLS 1.2',
      observedCipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
      timestamp: '2026-03-22T10:16:00Z',
      mismatch: true,
    },
    {
      id: 'rt-003',
      serviceName: 'user-auth',
      observedTlsVersion: 'TLS 1.2',
      configuredTlsVersion: 'TLS 1.2',
      observedCipherSuite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      timestamp: '2026-03-22T10:17:00Z',
      mismatch: false,
    },
    {
      id: 'rt-004',
      serviceName: 'legacy-adapter',
      observedTlsVersion: 'SSL 3.0',
      configuredTlsVersion: 'TLS 1.2',
      observedCipherSuite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
      timestamp: '2026-03-22T10:18:00Z',
      mismatch: true,
    },
    {
      id: 'rt-005',
      serviceName: 'notification-service',
      observedTlsVersion: 'TLS 1.3',
      configuredTlsVersion: 'TLS 1.3',
      observedCipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
      timestamp: '2026-03-22T10:19:00Z',
      mismatch: false,
    },
    {
      id: 'rt-006',
      serviceName: 'data-pipeline',
      observedTlsVersion: 'TLS 1.1',
      configuredTlsVersion: 'TLS 1.2',
      observedCipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA',
      timestamp: '2026-03-22T10:20:00Z',
      mismatch: true,
    },
  ],
  tlsVersionChart: [
    { version: 'SSL 3.0', configured: 0, observed: 1 },
    { version: 'TLS 1.0', configured: 0, observed: 1 },
    { version: 'TLS 1.1', configured: 0, observed: 1 },
    { version: 'TLS 1.2', configured: 3, observed: 1 },
    { version: 'TLS 1.3', configured: 3, observed: 2 },
  ],
};

export const MOCK_ENRICHED_FINDINGS: EnrichedFinding[] = [
  {
    findingId: 'f-007',
    file: 'network/tls_client.py',
    title: 'CERT_NONE — SSL verification disabled',
    staticTls: 'TLS 1.2',
    runtimeTls: 'TLS 1.0',
    mismatch: true,
    lastSeen: '2026-03-22T10:16:00Z',
  },
  {
    findingId: 'f-001',
    file: 'SSLConfig.java',
    title: 'Certificate validation disabled',
    staticTls: 'TLS 1.2',
    runtimeTls: 'TLS 1.2',
    mismatch: false,
    lastSeen: '2026-03-22T10:17:00Z',
  },
];

export function getRuntimeSummary(_projectId: string): RuntimeSummary {
  return MOCK_RUNTIME_SUMMARY;
}

export function getEnrichedFindings(_scanId: string): EnrichedFinding[] {
  return MOCK_ENRICHED_FINDINGS;
}
