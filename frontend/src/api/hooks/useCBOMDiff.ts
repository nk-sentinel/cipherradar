import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { CBOMDiffData, ScanSelector } from '@/mocks/data/cbomDiff.ts';

/**
 * Fetch CBOM diff between two scans.
 * Real API endpoint: GET /api/v1/cbom/diff?base=...&target=...
 */
export function useCBOMDiff(baseScanId: string, targetScanId: string) {
  return useQuery({
    queryKey: ['cbom-diff', baseScanId, targetScanId],
    queryFn: async () => {
      try {
        return await apiClient<CBOMDiffData>(
          `/cbom/diff?base=${baseScanId}&target=${targetScanId}`,
        );
      } catch {
        if (import.meta.env.DEV) {
          const { getCBOMDiff } = await import('@/mocks/data/cbomDiff.ts');
          return getCBOMDiff();
        }
        throw new Error('Failed to fetch CBOM diff');
      }
    },
    enabled: !!baseScanId && !!targetScanId,
    staleTime: 30_000,
  });
}

/**
 * Fetch available scans for the diff selector.
 * Real API endpoint: GET /api/v1/cbom/scans
 */
export function useScanSelectors() {
  return useQuery({
    queryKey: ['cbom-scans'],
    queryFn: async () => {
      try {
        return await apiClient<ScanSelector[]>('/cbom/scans');
      } catch {
        if (import.meta.env.DEV) {
          const { getScanSelectors } = await import('@/mocks/data/cbomDiff.ts');
          return getScanSelectors();
        }
        throw new Error('Failed to fetch scan selectors');
      }
    },
    staleTime: 60_000,
  });
}
