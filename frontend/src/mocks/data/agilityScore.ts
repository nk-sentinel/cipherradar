export interface AgilityFactor {
  name: string;
  weight: number;
  score: number;
  details: string;
}

export interface AgilityScoreData {
  overallScore: number;
  factors: AgilityFactor[];
  recommendations: string[];
  repoComparison: AgilityRepoComparison[];
}

export interface AgilityRepoComparison {
  repoId: string;
  repoName: string;
  score: number;
  algorithmDiversity: number;
  migrationReadiness: number;
}

export const MOCK_AGILITY_SCORE: AgilityScoreData = {
  overallScore: 62,
  factors: [
    {
      name: 'Algorithm Diversity',
      weight: 25,
      score: 70,
      details: 'Uses 4 different algorithm families. Good diversity but some legacy algorithms remain.',
    },
    {
      name: 'Abstraction Layer',
      weight: 20,
      score: 45,
      details: 'Only 45% of crypto calls go through an abstraction layer. Direct library calls reduce agility.',
    },
    {
      name: 'Configuration Externalization',
      weight: 20,
      score: 55,
      details: '55% of crypto parameters are externalized to configuration. Some hardcoded values detected.',
    },
    {
      name: 'PQC Readiness',
      weight: 20,
      score: 72,
      details: 'Most symmetric algorithms are quantum-safe. 3 asymmetric algorithms need migration paths.',
    },
    {
      name: 'Library Currency',
      weight: 15,
      score: 80,
      details: 'Crypto libraries are within 1 major version of latest. OpenSSL 3.x detected.',
    },
  ],
  recommendations: [
    'Introduce a crypto abstraction layer to decouple business logic from specific algorithm implementations.',
    'Externalize algorithm parameters (key sizes, cipher modes) to configuration files.',
    'Replace 3 remaining DES/3DES usages with AES-256-GCM for immediate security improvement.',
    'Plan ML-KEM (Kyber) migration for RSA-2048 key exchanges before 2030 CNSA 2.0 deadline.',
    'Update Bouncy Castle from 1.70 to 1.78 to gain PQC algorithm support.',
  ],
  repoComparison: [
    { repoId: 'repo-1', repoName: 'payment-api', score: 62, algorithmDiversity: 70, migrationReadiness: 55 },
    { repoId: 'repo-2', repoName: 'auth-service', score: 78, algorithmDiversity: 85, migrationReadiness: 72 },
    { repoId: 'repo-3', repoName: 'data-pipeline', score: 45, algorithmDiversity: 40, migrationReadiness: 50 },
    { repoId: 'repo-4', repoName: 'mobile-backend', score: 71, algorithmDiversity: 65, migrationReadiness: 78 },
  ],
};

export function getAgilityScore(_repoId: string): AgilityScoreData {
  return MOCK_AGILITY_SCORE;
}
