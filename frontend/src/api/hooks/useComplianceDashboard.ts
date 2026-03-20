import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { ComplianceDashboardData } from '@/mocks/data/complianceDashboard.ts';

/**
 * Fetch enhanced compliance dashboard data.
 * Real API endpoint: GET /api/v1/compliance/dashboard
 */
export function useComplianceDashboard() {
  return useQuery({
    queryKey: ['compliance', 'dashboard'],
    queryFn: () => apiClient<ComplianceDashboardData>('/compliance/dashboard'),
    staleTime: 30_000,
  });
}
