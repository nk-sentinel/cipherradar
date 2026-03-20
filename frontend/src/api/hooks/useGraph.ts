import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { GraphData } from '@/mocks/data/graph.ts';

/**
 * Fetch crypto dependency graph data.
 * Real API endpoint: GET /api/v1/graph
 */
export function useGraph() {
  return useQuery({
    queryKey: ['graph'],
    queryFn: () => apiClient<GraphData>('/graph'),
    staleTime: 60_000,
  });
}
