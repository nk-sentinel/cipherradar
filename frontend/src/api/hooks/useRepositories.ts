import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { Repository, RepositoryDetail } from '@/types/api.d.ts';

/**
 * Fetch all repositories.
 * Real API endpoint: GET /api/v1/projects
 */
export function useRepositories() {
  return useQuery({
    queryKey: ['repositories'],
    queryFn: async () => {
      try {
        return await apiClient<Repository[]>('/projects');
      } catch {
        if (import.meta.env.DEV) {
          const { MOCK_REPOSITORIES } = await import('@/mocks/data/repositories.ts');
          return MOCK_REPOSITORIES;
        }
        throw new Error('Failed to fetch repositories');
      }
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch a single repository by ID.
 * Real API endpoint: GET /api/v1/projects/:id
 */
export function useRepository(id: string) {
  return useQuery({
    queryKey: ['repository', id],
    queryFn: async () => {
      try {
        return await apiClient<RepositoryDetail>(`/projects/${id}`);
      } catch {
        if (import.meta.env.DEV) {
          const { MOCK_REPOSITORY_DETAILS } = await import(
            '@/mocks/data/repositories.ts'
          );
          const detail = MOCK_REPOSITORY_DETAILS[id];
          if (!detail) throw new Error('Repository not found');
          return detail;
        }
        throw new Error('Failed to fetch repository');
      }
    },
    enabled: !!id,
    staleTime: 30_000,
  });
}
