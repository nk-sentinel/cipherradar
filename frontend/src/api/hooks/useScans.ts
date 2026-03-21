import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { ScanSummary, ScanDetail } from '@/mocks/data/scans.ts';

/**
 * Fetch all scans for a repository.
 * Real API endpoint: GET /api/v1/repos/:repoId/scans
 */
export function useScans(repoId: string) {
  return useQuery<ScanSummary[]>({
    queryKey: ['scans', repoId],
    queryFn: async () => {
      try {
        return await apiClient<ScanSummary[]>(`/repos/${repoId}/scans`);
      } catch {
          const { getScansForRepo } = await import('@/mocks/data/scans.ts');
          return getScansForRepo(repoId);
    }
    },
    staleTime: 30_000,
    enabled: !!repoId,
  });
}

/**
 * Fetch a single scan with findings summary.
 * Real API endpoint: GET /api/v1/scans/:scanId
 */
export function useScan(scanId: string) {
  return useQuery<ScanDetail | undefined>({
    queryKey: ['scan', scanId],
    queryFn: async () => {
      try {
        return await apiClient<ScanDetail>(`/scans/${scanId}`);
      } catch {
          const { getScanDetail } = await import('@/mocks/data/scans.ts');
          return getScanDetail(scanId);
    }
    },
    staleTime: 30_000,
    enabled: !!scanId,
  });
}
