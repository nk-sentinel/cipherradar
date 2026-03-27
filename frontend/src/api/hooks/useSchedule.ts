import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client';
import { useToast } from '@/lib/use-toast';

export interface ScheduleData {
  preset: 'off' | 'daily' | 'weekly';
  hour: number;
  timezone: string;
  source: 'project' | 'group' | 'org' | 'none';
  nextRun: string | null;
}

export interface SaveScheduleParams {
  preset: 'off' | 'daily' | 'weekly';
  hour: number;
  timezone: string;
}

export function useSchedule(scopeType: 'projects' | 'groups' | 'orgs', scopeId: string) {
  return useQuery<ScheduleData>({
    queryKey: ['schedule', scopeType, scopeId],
    queryFn: async (): Promise<ScheduleData> => {
      return apiClient<ScheduleData>(`/${scopeType}/${scopeId}/schedule`);
    },
    staleTime: 60_000,
    enabled: !!scopeId,
  });
}

export function useSaveSchedule(scopeType: 'projects' | 'groups' | 'orgs', scopeId: string) {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (params: SaveScheduleParams) => {
      return apiClient(`/${scopeType}/${scopeId}/schedule`, {
        method: 'PUT',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['schedule', scopeType, scopeId] });
      toast({ title: 'Schedule saved', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to save schedule', description: err.message, variant: 'error' });
    },
  });
}
