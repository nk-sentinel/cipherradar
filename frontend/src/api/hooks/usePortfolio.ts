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
    queryFn: () => apiClient<PortfolioSummaryData>('/portfolio/summary'),
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
    queryFn: () => apiClient<HeatMapData>('/portfolio/heatmap'),
    staleTime: 30_000,
  });
}
