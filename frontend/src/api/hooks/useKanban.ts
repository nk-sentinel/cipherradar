import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { KanbanCard } from '@/mocks/data/kanban.ts';

export function useKanbanCards() {
  return useQuery({
    queryKey: ['kanban'],
    queryFn: async () => {
      try {
        const data = await apiClient<KanbanCard[] | { items: KanbanCard[] }>('/kanban');
        if (data) return Array.isArray(data) ? data : (data.items ?? []);
      } catch (err) {
        if (import.meta.env.DEV) {
          console.warn('[CipherRadar] API unavailable, using mock data for kanban');
          const { getKanbanCards } = await import('@/mocks/data/kanban.ts');
          return getKanbanCards();
        }
        throw err;
      }
    },
    staleTime: 30_000,
  });
}
