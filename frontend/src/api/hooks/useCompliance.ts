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
    queryFn: () => apiClient<PortfolioComplianceData>('/compliance/portfolio'),
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
    queryFn: () => apiClient<RepoComplianceData>(`/repos/${repoId}/compliance`),
    enabled: !!repoId,
    staleTime: 30_000,
  });
}
