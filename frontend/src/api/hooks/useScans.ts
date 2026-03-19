import { useQuery } from '@tanstack/react-query';
import {
  getScansForRepo,
  getScanDetail,
  type ScanSummary,
  type ScanDetail,
} from '@/mocks/data/scans.ts';

/**
 * Fetch all scans for a repository.
 * Uses mock data in development; will switch to apiClient once backend is ready.
 */
export function useScans(repoId: string) {
  return useQuery<ScanSummary[]>({
    queryKey: ['scans', repoId],
    queryFn: async () => {
      // Simulate network latency
      await new Promise((r) => setTimeout(r, 100));
      return getScansForRepo(repoId);
    },
    staleTime: 30_000,
    enabled: !!repoId,
  });
}

/**
 * Fetch a single scan with findings summary.
 * Uses mock data in development; will switch to apiClient once backend is ready.
 */
export function useScan(scanId: string) {
  return useQuery<ScanDetail | undefined>({
    queryKey: ['scan', scanId],
    queryFn: async () => {
      // Simulate network latency
      await new Promise((r) => setTimeout(r, 100));
      return getScanDetail(scanId);
    },
    staleTime: 30_000,
    enabled: !!scanId,
  });
}
