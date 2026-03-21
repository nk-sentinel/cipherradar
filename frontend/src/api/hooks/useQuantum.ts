import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  PortfolioQuantumData,
  RepoQuantumData,
} from '@/mocks/data/quantum.ts';

/**
 * Fetch org-wide quantum readiness data.
 * Real API endpoint: GET /api/v1/quantum/portfolio
 */
export function useQuantumRisk() {
  return useQuery({
    queryKey: ['quantum', 'portfolio'],
    queryFn: async () => {
      try {
        const data = await apiClient<PortfolioQuantumData>('/quantum/portfolio');
        if (data) return data;
      } catch {
          const { getPortfolioQuantum } = await import('@/mocks/data/quantum.ts');
          return getPortfolioQuantum();
    }
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch quantum readiness data for a single repository.
 * Real API endpoint: GET /api/v1/repos/:repoId/quantum
 */
export function useQuantumRiskForRepo(repoId: string) {
  return useQuery({
    queryKey: ['quantum', 'repo', repoId],
    queryFn: async () => {
      try {
        const data = await apiClient<RepoQuantumData>(`/repos/${repoId}/quantum`);
        if (data) return data;
      } catch {
          const { getRepoQuantum } = await import('@/mocks/data/quantum.ts');
          const data = getRepoQuantum(repoId);
          if (!data) throw new Error('Repo not found');
          return data;
    }
    },
    enabled: !!repoId,
    staleTime: 30_000,
  });
}
