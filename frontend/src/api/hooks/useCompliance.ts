import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  PortfolioComplianceData,
  RepoComplianceData,
} from '@/mocks/data/compliance.ts';

/**
 * Fetch org-wide compliance scores.
 * Real API endpoint: GET /api/v1/compliance/portfolio
 */
export function useCompliance() {
  return useQuery({
    queryKey: ['compliance', 'portfolio'],
    queryFn: async () => {
      try {
        return await apiClient<PortfolioComplianceData>('/compliance/portfolio');
      } catch {
          const { getPortfolioCompliance } = await import('@/mocks/data/compliance.ts');
          return getPortfolioCompliance();
    }
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch compliance data for a single repository.
 * Real API endpoint: GET /api/v1/repos/:repoId/compliance
 */
export function useComplianceForRepo(repoId: string) {
  return useQuery({
    queryKey: ['compliance', 'repo', repoId],
    queryFn: async () => {
      try {
        return await apiClient<RepoComplianceData>(`/repos/${repoId}/compliance`);
      } catch {
          const { getRepoCompliance } = await import('@/mocks/data/compliance.ts');
          const data = getRepoCompliance(repoId);
          if (!data) throw new Error('Repo not found');
          return data;
    }
    },
    enabled: !!repoId,
    staleTime: 30_000,
  });
}
