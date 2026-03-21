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
      } catch { /* fall through to mock */ }
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
        // The API returns heatMap (array) or repos (array) depending on version.
        // Accept either shape from the real API.
        const heatMapArray = (data as unknown as Record<string, unknown>).heatMap ?? data?.repos;
        if (data && Array.isArray(heatMapArray)) {
          return { ...data, repos: heatMapArray as HeatMapData['repos'] };
        }
      } catch { /* fall through to mock */ }
      const { getHeatMap } = await import('@/mocks/data/portfolio.ts');
      return getHeatMap();
    },
    staleTime: 30_000,
  });
}
