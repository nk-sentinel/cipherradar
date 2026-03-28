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
        const data = await apiClient<Repository[] | { items: Repository[] }>('/projects');
        if (data) return Array.isArray(data) ? data : (data.items ?? []);
      } catch {
          const { MOCK_REPOSITORIES } = await import('@/mocks/data/repositories.ts');
          return MOCK_REPOSITORIES;
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
        const data = await apiClient<RepositoryDetail>(`/projects/${id}`);
        if (data) return data;
      } catch {
          const { MOCK_REPOSITORY_DETAILS } = await import(
            '@/mocks/data/repositories.ts'
          );
          const detail = MOCK_REPOSITORY_DETAILS[id];
          if (!detail) throw new Error('Repository not found');
          return detail;
    }
    },
    enabled: !!id,
    staleTime: 30_000,
  });
}
