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
        const data = await apiClient<ComplianceDashboardData>('/compliance/trends');
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for compliance dashboard');
          const { getComplianceDashboard } = await import(
            '@/mocks/data/complianceDashboard.ts'
          );
          return getComplianceDashboard();
        }
        throw err;
      }
    },
    staleTime: 30_000,
  });
}
