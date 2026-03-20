import { useQuery } from '@tanstack/react-query';
import type { GraphData } from '@/mocks/data/graph.ts';

/**
 * Fetch crypto dependency graph data.
 * No backend endpoint yet — always uses mock data.
 */
export function useGraph() {
  return useQuery({
    queryKey: ['graph'],
    queryFn: async () => {
      const { getGraphData } = await import('@/mocks/data/graph.ts');
      return getGraphData() as GraphData;
    },
    staleTime: 60_000,
  });
}
