import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { Org } from '@/mocks/data/admin.ts';

/**
 * Fetch the list of orgs the current user belongs to.
 * Real API endpoint: GET /api/v1/user/orgs
 */
export function useUserOrgs() {
  return useQuery({
    queryKey: ['user-orgs'],
    queryFn: async () => {
      try {
        return await apiClient<Org[]>('/user/orgs');
      } catch {
        if (import.meta.env.DEV) {
          const { getUserOrgs } = await import('@/mocks/data/admin.ts');
          return getUserOrgs();
        }
        throw new Error('Failed to fetch user orgs');
      }
    },
    staleTime: 60_000,
  });
}
