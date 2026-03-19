import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { Repository, RepositoryDetail } from '@/types/api.d.ts';

export function useRepositories() {
  return useQuery({
    queryKey: ['repositories'],
    queryFn: () => apiClient<Repository[]>('/projects'),
    staleTime: 30_000,
  });
}

export function useRepository(id: string) {
  return useQuery({
    queryKey: ['repository', id],
    queryFn: () => apiClient<RepositoryDetail>(`/projects/${id}`),
    enabled: !!id,
    staleTime: 30_000,
  });
}
