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
        // Validate expected shape before returning
        if (data && Array.isArray(data.severityDistribution) && Array.isArray(data.topRiskRepos)) {
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
        if (data && Array.isArray(data.repos)) return data;
      } catch { /* fall through to mock */ }
      const { getHeatMap } = await import('@/mocks/data/portfolio.ts');
      return getHeatMap();
    },
    staleTime: 30_000,
  });
}
