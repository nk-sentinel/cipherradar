import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  PortfolioComplianceData,
  RepoComplianceData,
} from '@/mocks/data/compliance.ts';

/**
 * Fetch org-wide compliance scores.
 * Real API endpoint: GET /api/v1/portfolio/compliance
 */
export function useCompliance() {
  return useQuery({
    queryKey: ['compliance', 'portfolio'],
    queryFn: async () => {
      try {
        const data = await apiClient<PortfolioComplianceData>('/portfolio/compliance');
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for portfolio compliance');
          const { getPortfolioCompliance } = await import('@/mocks/data/compliance.ts');
          return getPortfolioCompliance();
        }
        throw err;
      }
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch compliance data for a single repository.
 * Real API endpoint: GET /api/v1/projects/:repoId/compliance/nist-800-131a
 */
export function useComplianceForRepo(repoId: string) {
  return useQuery({
    queryKey: ['compliance', 'repo', repoId],
    queryFn: async () => {
      try {
        const data = await apiClient<RepoComplianceData>(`/projects/${repoId}/compliance/nist-800-131a`);
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for repo compliance');
          const { getRepoCompliance } = await import('@/mocks/data/compliance.ts');
          const data = getRepoCompliance(repoId);
          if (!data) throw new Error('Repo not found');
          return data;
        }
        throw err;
      }
    },
    enabled: !!repoId,
    staleTime: 30_000,
  });
}
