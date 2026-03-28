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
      } catch {
          const { getKanbanCards } = await import('@/mocks/data/kanban.ts');
          return getKanbanCards();
      }
    },
    staleTime: 30_000,
  });
}
