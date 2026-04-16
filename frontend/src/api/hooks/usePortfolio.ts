import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  PortfolioSummaryData,
  HeatMapData,
} from '@/mocks/data/portfolio.ts';

/**
 * Fetch portfolio dashboard summary.
 * Real API endpoint: GET /api/v1/portfolio/summary
 */
export function usePortfolioSummary() {
  return useQuery({
    queryKey: ['portfolio', 'summary'],
    queryFn: async () => {
      try {
        const data = await apiClient<PortfolioSummaryData>('/portfolio/summary');
        // Validate the shape matches what the real API returns (camelCase fields).
        // The API returns totalRepos (number) and either topRiskRepos or
        // topRiskiestRepos (array). Accept either field name.
        if (
          data &&
          typeof data.totalRepos === 'number' &&
          typeof data.totalFindings === 'number'
        ) {
          return data;
        }
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for portfolio summary');
      }
      if (!import.meta.env.DEV) {
        throw new Error('Portfolio summary API unavailable');
      }
      const { getPortfolioSummary } = await import('@/mocks/data/portfolio.ts');
      return getPortfolioSummary();
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch heat map data (repos x severity).
 * Real API endpoint: GET /api/v1/portfolio/heatmap
 */
export function useHeatMap() {
  return useQuery({
    queryKey: ['portfolio', 'heatmap'],
    queryFn: async () => {
      try {
        const data = await apiClient<HeatMapData>('/portfolio/heatmap');
        // The API may return { groups: [...] }, { heatMap: [...] }, or { repos: [...] }.
        // Normalise to { repos: [...] } for the frontend.
        const raw = data as unknown as Record<string, unknown>;
        const heatMapArray = raw.groups ?? raw.heatMap ?? raw.repos;
        if (data && Array.isArray(heatMapArray)) {
          // Map group-shaped or repo-shaped items to HeatMapCell shape
          const repos = (heatMapArray as Record<string, unknown>[]).map((item, idx) => ({
            repoId: (item.repoId as string) ?? (item.projectId as string) ?? (item.id as string) ?? `group-${String(idx)}`,
            repoName: (item.repoName as string) ?? (item.projectName as string) ?? (item.name as string) ?? '',
            critical: (item.critical as number) ?? (item.criticalCount as number) ?? 0,
            high: (item.high as number) ?? (item.highCount as number) ?? 0,
            medium: (item.medium as number) ?? (item.mediumCount as number) ?? 0,
            low: (item.low as number) ?? (item.lowCount as number) ?? 0,
            info: (item.info as number) ?? (item.infoCount as number) ?? 0,
          }));
          return { repos } as HeatMapData;
        }
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for heat map');
      }
      if (!import.meta.env.DEV) {
        throw new Error('Heat map API unavailable');
      }
      const { getHeatMap } = await import('@/mocks/data/portfolio.ts');
      return getHeatMap();
    },
    staleTime: 30_000,
  });
}
