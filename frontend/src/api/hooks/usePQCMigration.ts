import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

export interface MigrationOverview {
  totalFindings: number;
  vulnerable: number;
  safe: number;
  unknown: number;
  percentVulnerable: number;
  percentSafe: number;
  percentUnknown: number;
}

export interface AlgorithmFamilyProgress {
  family: string;
  total: number;
  vulnerable: number;
  safe: number;
  unknown: number;
  percentMigrated: number;
}

export interface LaggingProject {
  projectId: string;
  projectName: string;
  vulnerableCount: number;
  totalCount: number;
  percentVulnerable: number;
}

export interface PQCMigrationResponse {
  overview: MigrationOverview;
  families: AlgorithmFamilyProgress[];
  laggingProjects: LaggingProject[];
}

/**
 * Fetch PQC migration progress from GET /api/v1/portfolio/pqc-migration.
 * Falls back to mock data if endpoint is not ready.
 */
export function usePQCMigration() {
  return useQuery<PQCMigrationResponse>({
    queryKey: ['pqc-migration'],
    queryFn: async () => {
      try {
        const data = await apiClient<PQCMigrationResponse>('/portfolio/pqc-migration');
        if (data && data.overview) return data;
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for PQC migration');
      }
      if (!import.meta.env.DEV) {
        throw new Error('PQC migration API unavailable');
      }
      // Inline mock data as fallback (dev only)
      return {
        overview: {
          totalFindings: 120,
          vulnerable: 45,
          safe: 55,
          unknown: 20,
          percentVulnerable: 37.5,
          percentSafe: 45.83,
          percentUnknown: 16.67,
        },
        families: [
          { family: 'RSA', total: 40, vulnerable: 30, safe: 5, unknown: 5, percentMigrated: 12.5 },
          { family: 'ECDSA', total: 25, vulnerable: 10, safe: 12, unknown: 3, percentMigrated: 48.0 },
          { family: 'AES', total: 30, vulnerable: 0, safe: 28, unknown: 2, percentMigrated: 93.33 },
          { family: 'SHA-2', total: 15, vulnerable: 0, safe: 10, unknown: 5, percentMigrated: 66.67 },
          { family: 'DES', total: 5, vulnerable: 5, safe: 0, unknown: 0, percentMigrated: 0.0 },
          { family: 'MD5', total: 5, vulnerable: 0, safe: 0, unknown: 5, percentMigrated: 0.0 },
        ],
        laggingProjects: [
          { projectId: 'proj-001', projectName: 'payment-service', vulnerableCount: 18, totalCount: 25, percentVulnerable: 72.0 },
          { projectId: 'proj-002', projectName: 'auth-api', vulnerableCount: 12, totalCount: 30, percentVulnerable: 40.0 },
          { projectId: 'proj-003', projectName: 'data-pipeline', vulnerableCount: 8, totalCount: 35, percentVulnerable: 22.86 },
          { projectId: 'proj-004', projectName: 'mobile-backend', vulnerableCount: 7, totalCount: 30, percentVulnerable: 23.33 },
        ],
      };
    },
    staleTime: 30_000,
  });
}
