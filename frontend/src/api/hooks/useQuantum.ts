import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  PortfolioQuantumData,
  RepoQuantumData,
} from '@/mocks/data/quantum.ts';

/**
 * Fetch org-wide quantum readiness data.
 * Real API endpoint: GET /api/v1/portfolio/quantum
 */
export function useQuantumRisk() {
  return useQuery({
    queryKey: ['quantum', 'portfolio'],
    queryFn: async () => {
      try {
        const data = await apiClient<PortfolioQuantumData>('/portfolio/quantum');
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for portfolio quantum');
          const { getPortfolioQuantum } = await import('@/mocks/data/quantum.ts');
          return getPortfolioQuantum();
        }
        throw err;
      }
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch quantum readiness data for a single repository.
 * Real API endpoint: GET /api/v1/projects/:repoId/quantum-risk
 */
export function useQuantumRiskForRepo(repoId: string) {
  return useQuery({
    queryKey: ['quantum', 'repo', repoId],
    queryFn: async () => {
      try {
        const data = await apiClient<RepoQuantumData>(`/projects/${repoId}/quantum-risk`);
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for repo quantum');
          const { getRepoQuantum } = await import('@/mocks/data/quantum.ts');
          const data = getRepoQuantum(repoId);
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
