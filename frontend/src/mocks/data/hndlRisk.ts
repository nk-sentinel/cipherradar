export type DataSensitivity = 'public' | 'internal' | 'confidential' | 'restricted';
export type UrgencyLevel = 'urgent' | 'high' | 'medium' | 'low';

export interface QuantumExposure {
  algorithm: string;
  usageCount: number;
  exposureType: 'key-exchange' | 'signature' | 'encryption';
  quantumBreakYear: number;
}

export interface MoscaInequality {
  shelfLife: number;
  migrationTime: number;
  quantumDeadline: number;
  currentYear: number;
  isAtRisk: boolean;
}

export interface HNDLRiskData {
  riskScore: number;
  urgency: UrgencyLevel;
  dataSensitivity: DataSensitivity;
  quantumExposures: QuantumExposure[];
  mosca: MoscaInequality;
  recommendations: string[];
}

function computeUrgency(score: number): UrgencyLevel {
  if (score >= 0.8) return 'urgent';
  if (score >= 0.6) return 'high';
  if (score >= 0.3) return 'medium';
  return 'low';
}

export const MOCK_HNDL_RISK: HNDLRiskData = {
  riskScore: 0.72,
  urgency: 'high',
  dataSensitivity: 'confidential',
  quantumExposures: [
    {
      algorithm: 'RSA-2048',
      usageCount: 12,
      exposureType: 'key-exchange',
      quantumBreakYear: 2030,
    },
    {
      algorithm: 'ECDSA P-256',
      usageCount: 8,
      exposureType: 'signature',
      quantumBreakYear: 2032,
    },
    {
      algorithm: 'ECDH P-256',
      usageCount: 5,
      exposureType: 'key-exchange',
      quantumBreakYear: 2032,
    },
    {
      algorithm: 'RSA-4096',
      usageCount: 3,
      exposureType: 'signature',
      quantumBreakYear: 2035,
    },
  ],
  mosca: {
    shelfLife: 15,
    migrationTime: 3,
    quantumDeadline: 2030,
    currentYear: 2026,
    isAtRisk: true,
  },
  recommendations: [
    'Begin ML-KEM (Kyber) evaluation for RSA-2048 key exchanges immediately — HNDL risk is high.',
    'Encrypted data with 15-year shelf life captured today could be decrypted by 2030 quantum computers.',
    'Prioritize replacing ECDSA P-256 signatures with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+).',
    'Implement hybrid TLS (classical + PQC) for data-in-transit protection during transition period.',
    'Conduct data classification review to identify highest-sensitivity assets needing earliest migration.',
  ],
};

export function getHNDLRisk(_repoId: string, sensitivity?: DataSensitivity): HNDLRiskData {
  if (sensitivity && sensitivity !== MOCK_HNDL_RISK.dataSensitivity) {
    const adjustedScore =
      sensitivity === 'restricted' ? 0.92 :
      sensitivity === 'confidential' ? 0.72 :
      sensitivity === 'internal' ? 0.45 :
      0.18;
    return {
      ...MOCK_HNDL_RISK,
      dataSensitivity: sensitivity,
      riskScore: adjustedScore,
      urgency: computeUrgency(adjustedScore),
    };
  }
  return MOCK_HNDL_RISK;
}
