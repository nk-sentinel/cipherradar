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
    queryFn: () => apiClient<PortfolioQuantumData>('/quantum/portfolio'),
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
    queryFn: () => apiClient<RepoQuantumData>(`/repos/${repoId}/quantum`),
    enabled: !!repoId,
    staleTime: 30_000,
  });
}
