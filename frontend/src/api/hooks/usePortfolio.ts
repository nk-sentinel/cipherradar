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
        return await apiClient<PortfolioSummaryData>('/portfolio/summary');
      } catch {
        if (import.meta.env.DEV) {
          const { getPortfolioSummary } = await import('@/mocks/data/portfolio.ts');
          return getPortfolioSummary();
        }
        throw new Error('Failed to fetch portfolio summary');
      }
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
        return await apiClient<HeatMapData>('/portfolio/heatmap');
      } catch {
        if (import.meta.env.DEV) {
          const { getHeatMap } = await import('@/mocks/data/portfolio.ts');
          return getHeatMap();
        }
        throw new Error('Failed to fetch heat map data');
      }
    },
    staleTime: 30_000,
  });
}
