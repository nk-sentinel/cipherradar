import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { ComplianceDashboardData } from '@/mocks/data/complianceDashboard.ts';

/**
 * Fetch enhanced compliance dashboard data.
 * Real API endpoint: GET /api/v1/compliance/trends
 */
export function useComplianceDashboard() {
  return useQuery({
    queryKey: ['compliance', 'dashboard'],
    queryFn: async () => {
      try {
        return await apiClient<ComplianceDashboardData>('/compliance/trends');
      } catch {
        if (import.meta.env.DEV) {
          const { getComplianceDashboard } = await import(
            '@/mocks/data/complianceDashboard.ts'
          );
          return getComplianceDashboard();
        }
        throw new Error('Failed to fetch compliance dashboard data');
      }
    },
    staleTime: 30_000,
  });
}
