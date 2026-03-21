import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

export function useTriggerScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (projectId: string) => {
      return apiClient(`/projects/${projectId}/scans/trigger`, { method: 'POST' });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}
