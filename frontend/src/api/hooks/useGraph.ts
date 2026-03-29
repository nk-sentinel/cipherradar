import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { GraphData } from '@/mocks/data/graph.ts';

/**
 * Fetch crypto dependency graph data.
 * Calls GET /api/v1/graph — falls back to mock in dev only.
 */
export function useGraph() {
  return useQuery({
    queryKey: ['graph'],
    queryFn: async () => {
      try {
        const data = await apiClient<GraphData>('/graph');
        if (data) return data;
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] Graph API unavailable, using mock data');
          const { getGraphData } = await import('@/mocks/data/graph.ts');
          return getGraphData() as GraphData;
        }
        throw err;
      }
    },
    staleTime: 60_000,
  });
}
