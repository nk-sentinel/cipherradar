import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { RuntimeSummary, EnrichedFinding } from '@/mocks/data/runtime.ts';

/**
 * Fetch runtime observation summary for a project.
 * Real API endpoint: GET /api/v1/projects/:projectId/runtime/summary
 * Falls back to mock data if endpoint is not ready.
 */
export function useRuntimeSummary(projectId: string) {
  return useQuery<RuntimeSummary>({
    queryKey: ['runtime', 'summary', projectId],
    queryFn: async (): Promise<any> => {
      try {
        const data = await apiClient<RuntimeSummary>(
          `/projects/${projectId}/runtime/summary`,
        );
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for runtime summary');
          const { getRuntimeSummary } = await import('@/mocks/data/runtime.ts');
          return getRuntimeSummary(projectId);
        }
        throw err;
      }
    },
    staleTime: 30_000,
    enabled: !!projectId,
  });
}

/**
 * Fetch enriched findings (static + runtime) for a scan.
 * Real API endpoint: GET /api/v1/scans/:scanId/runtime/enriched
 * Falls back to mock data if endpoint is not ready.
 */
export function useEnrichedFindings(scanId: string) {
  return useQuery<EnrichedFinding[]>({
    queryKey: ['runtime', 'enriched', scanId],
    queryFn: async (): Promise<any> => {
      try {
        const data = await apiClient<EnrichedFinding[] | { items: EnrichedFinding[] }>(
          `/scans/${scanId}/runtime/enriched`,
        );
        if (data) return Array.isArray(data) ? data : (data.items ?? []);
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for enriched findings');
          const { getEnrichedFindings } = await import('@/mocks/data/runtime.ts');
          return getEnrichedFindings(scanId);
        }
        throw err;
      }
    },
    staleTime: 30_000,
    enabled: !!scanId,
  });
}
