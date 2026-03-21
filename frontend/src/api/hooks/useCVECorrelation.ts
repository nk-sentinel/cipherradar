import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { CVECorrelationData } from '@/mocks/data/cveCorrelation.ts';

/**
 * Fetch SBOM-CBOM CVE correlation data for a project.
 * Real API endpoint: GET /api/v1/projects/:projectId/sbom-cbom-link
 * Falls back to mock data if endpoint is not ready.
 */
export function useCVECorrelation(projectId: string) {
  return useQuery<CVECorrelationData>({
    queryKey: ['cve-correlation', projectId],
    queryFn: async (): Promise<any> => {
      try {
        const data = await apiClient<CVECorrelationData>(
          `/projects/${projectId}/sbom-cbom-link`,
        );
        if (data) return data;
      } catch {
        const { getCVECorrelation } = await import('@/mocks/data/cveCorrelation.ts');
        return getCVECorrelation(projectId);
      }
    },
    staleTime: 60_000,
    enabled: !!projectId,
  });
}
