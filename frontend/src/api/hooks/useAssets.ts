import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  AssetFilters,
  AssetSearchResult,
} from '@/mocks/data/assets.ts';

/**
 * Fetch paginated, filtered crypto assets.
 * Real API endpoint: GET /api/v1/assets?type=...&language=...&page=...&pageSize=...
 */
export function useAssets(filters: AssetFilters, page: number, pageSize = 15) {
  const params = new URLSearchParams();
  params.set('page', String(page));
  params.set('pageSize', String(pageSize));
  if (filters.type) params.set('type', filters.type);
  if (filters.language) params.set('language', filters.language);
  if (filters.quantumStatus) params.set('quantumStatus', filters.quantumStatus);
  if (filters.compliance) params.set('compliance', filters.compliance);
  if (filters.search) params.set('search', filters.search);

  return useQuery({
    queryKey: ['assets', filters, page, pageSize],
    queryFn: async () => {
      try {
        const data = await apiClient<AssetSearchResult>(`/assets?${params.toString()}`);
        if (data) {
          // The API may return { items: [...] } instead of { assets: [...] }.
          // Normalise so the frontend always sees data.assets.
          const raw = data as unknown as Record<string, unknown>;
          if (!data.assets && Array.isArray(raw.items)) {
            return { ...data, assets: raw.items as AssetSearchResult['assets'] };
          }
          return data;
        }
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for assets');
          const { searchAssets } = await import('@/mocks/data/assets.ts');
          return searchAssets(filters, page, pageSize);
        }
        throw err;
      }
    },
    staleTime: 30_000,
  });
}

/**
 * Search assets with a text query (convenience wrapper).
 * Real API endpoint: GET /api/v1/assets?search=...
 */
export function useAssetSearch(query: string, page = 1, pageSize = 15) {
  return useAssets({ search: query || undefined }, page, pageSize);
}
