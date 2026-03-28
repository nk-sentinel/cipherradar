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
        const data = await apiClient<CBOMDiffData>(
          `/cbom/diff?base=${baseScanId}&target=${targetScanId}`,
        );
        if (data) return data;
      } catch {
          const { getCBOMDiff } = await import('@/mocks/data/cbomDiff.ts');
          return getCBOMDiff();
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
        const data = await apiClient<ScanSelector[] | { items: ScanSelector[] }>('/cbom/scans');
        if (data) return Array.isArray(data) ? data : (data.items ?? []);
      } catch {
          const { getScanSelectors } = await import('@/mocks/data/cbomDiff.ts');
          return getScanSelectors();
    }
    },
    staleTime: 60_000,
  });
}
