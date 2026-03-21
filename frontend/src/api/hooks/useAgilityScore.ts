import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { AgilityScoreData } from '@/mocks/data/agilityScore.ts';

/**
 * Fetch crypto-agility score for a project.
 * Real API endpoint: GET /api/v1/projects/:projectId/agility-score
 * Falls back to mock data if endpoint is not ready.
 */
export function useAgilityScore(projectId: string) {
  return useQuery<AgilityScoreData>({
    queryKey: ['agility-score', projectId],
    queryFn: async (): Promise<any> => {
      try {
        const data = await apiClient<AgilityScoreData>(
          `/projects/${projectId}/agility-score`,
        );
        if (data) return data;
      } catch {
        const { getAgilityScore } = await import('@/mocks/data/agilityScore.ts');
        return getAgilityScore(projectId);
      }
    },
    staleTime: 60_000,
    enabled: !!projectId,
  });
}
