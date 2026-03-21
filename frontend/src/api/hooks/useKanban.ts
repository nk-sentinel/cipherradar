import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { KanbanCard } from '@/mocks/data/kanban.ts';

export function useKanbanCards() {
  return useQuery({
    queryKey: ['kanban'],
    queryFn: async () => {
      try {
        return await apiClient<KanbanCard[]>('/kanban');
      } catch {
        if (import.meta.env.DEV) {
          const { getKanbanCards } = await import('@/mocks/data/kanban.ts');
          return getKanbanCards();
        }
        throw new Error('Failed to fetch kanban cards');
      }
    },
    staleTime: 30_000,
  });
}
