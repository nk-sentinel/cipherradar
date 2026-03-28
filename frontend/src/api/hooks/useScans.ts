import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { ScanSummary, ScanDetail } from '@/mocks/data/scans.ts';

/**
 * Fetch all scans for a repository.
 * Real API endpoint: GET /api/v1/projects/:repoId/scans
 */
export function useScans(repoId: string) {
  return useQuery<ScanSummary[]>({
    queryKey: ['scans', repoId],
    queryFn: async (): Promise<ScanSummary[]> => {
      try {
        const data = await apiClient<ScanSummary[] | { items: ScanSummary[] }>(`/projects/${repoId}/scans`);
        if (data) return Array.isArray(data) ? data : (data.items ?? []);
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for scans');
      }
      if (!import.meta.env.DEV) {
        throw new Error('Scans API unavailable');
      }
      const { getScansForRepo } = await import('@/mocks/data/scans.ts');
      return getScansForRepo(repoId);
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
    queryFn: async (): Promise<ScanDetail | undefined> => {
      try {
        const data = await apiClient<ScanDetail>(`/scans/${scanId}`);
        if (data) return data;
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for scan detail');
      }
      if (!import.meta.env.DEV) {
        throw new Error('Scan detail API unavailable');
      }
      const { getScanDetail } = await import('@/mocks/data/scans.ts');
      return getScanDetail(scanId);
    },
    staleTime: 30_000,
    enabled: !!scanId,
  });
}
