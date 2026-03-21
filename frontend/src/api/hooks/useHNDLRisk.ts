import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { HNDLRiskData, DataSensitivity } from '@/mocks/data/hndlRisk.ts';

/**
 * Fetch HNDL (Harvest Now, Decrypt Later) risk assessment for a project.
 * Real API endpoint: GET /api/v1/projects/:projectId/hndl-risk
 * Falls back to mock data if endpoint is not ready.
 */
export function useHNDLRisk(projectId: string, sensitivity?: DataSensitivity) {
  return useQuery<HNDLRiskData>({
    queryKey: ['hndl-risk', projectId, sensitivity],
    queryFn: async (): Promise<any> => {
      try {
        const params = new URLSearchParams();
        if (sensitivity) params.set('sensitivity', sensitivity);
        const qs = params.toString();
        const url = `/projects/${projectId}/hndl-risk${qs ? `?${qs}` : ''}`;
        const data = await apiClient<HNDLRiskData>(url);
        if (data) return data;
      } catch {
        const { getHNDLRisk } = await import('@/mocks/data/hndlRisk.ts');
        return getHNDLRisk(projectId, sensitivity);
      }
    },
    staleTime: 60_000,
    enabled: !!projectId,
  });
}
