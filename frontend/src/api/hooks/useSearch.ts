import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client';

export type SearchResultType = 'project' | 'finding';

export interface SearchResultProject {
  type: 'project';
  id: string;
  name: string;
  group: string;
  provider: string;
}

export interface SearchResultFinding {
  type: 'finding';
  id: string;
  repoId: string;
  algorithm: string | null;
  file: string;
  severity: string;
  title: string;
}

export type SearchResult = SearchResultProject | SearchResultFinding;

export interface SearchResponse {
  results: SearchResult[];
  total: number;
}

/**
 * Debounced search hook.
 * GET /api/v1/search?q=<query>&type=<project|finding>
 * Falls back to mock data when the API is unavailable.
 */
export function useSearch(query: string, type?: SearchResultType) {
  return useQuery<SearchResponse>({
    queryKey: ['search', query, type],
    queryFn: async () => {
      try {
        const params = new URLSearchParams();
        if (query) params.set('q', query);
        if (type) params.set('type', type);
        const qs = params.toString();
        return await apiClient<SearchResponse>(`/search${qs ? `?${qs}` : ''}`);
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for search');
        // Fall back to mock search (dev only)
        const { MOCK_REPOSITORIES } = await import('@/mocks/data/repositories');
        const { MOCK_FINDINGS } = await import('@/mocks/data/findings');

        const results: SearchResult[] = [];
        const q = query.toLowerCase();

        if (!type || type === 'project') {
          for (const repo of MOCK_REPOSITORIES) {
            if (
              repo.name.toLowerCase().includes(q) ||
              repo.orgPath.toLowerCase().includes(q)
            ) {
              results.push({
                type: 'project',
                id: repo.id,
                name: repo.name,
                group: repo.orgPath.split('/')[0] ?? '',
                provider: repo.provider,
              });
            }
          }
        }

        if (!type || type === 'finding') {
          for (const finding of MOCK_FINDINGS) {
            if (
              finding.title.toLowerCase().includes(q) ||
              finding.file.toLowerCase().includes(q) ||
              (finding.algorithm?.toLowerCase().includes(q) ?? false)
            ) {
              results.push({
                type: 'finding',
                id: finding.id,
                repoId: finding.repoId,
                algorithm: finding.algorithm,
                file: finding.file,
                severity: finding.severity,
                title: finding.title,
              });
            }
          }
        }

        return { results, total: results.length };
      }
    },
    enabled: query.length >= 2,
    staleTime: 10_000,
  });
}
