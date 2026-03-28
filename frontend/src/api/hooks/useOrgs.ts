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
        const data = await apiClient<Org[] | { items: Org[] }>('/user/orgs');
        if (data) return Array.isArray(data) ? data : (data.items ?? []);
      } catch {
          const { getUserOrgs } = await import('@/mocks/data/admin.ts');
          return getUserOrgs();
    }
    },
    staleTime: 60_000,
  });
}
