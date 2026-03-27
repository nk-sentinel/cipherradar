import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client';
import { useToast } from '@/lib/use-toast';

export interface Promotion {
  from: string;
  to: string;
  promotedBy: string;
  promotedAt: string;
}

export interface ProvenanceData {
  scanId: string;
  environment: string;
  promotions: Promotion[];
}

export interface EnvironmentInfo {
  id: string;
  name: string;
  label: string;
}

export function useProvenance(scanId: string) {
  return useQuery<ProvenanceData>({
    queryKey: ['provenance', scanId],
    queryFn: async (): Promise<ProvenanceData> => {
      return apiClient<ProvenanceData>(`/scans/${scanId}/provenance`);
    },
    staleTime: 30_000,
    enabled: !!scanId,
  });
}

export function useEnvironments() {
  return useQuery<EnvironmentInfo[]>({
    queryKey: ['environments'],
    queryFn: async (): Promise<EnvironmentInfo[]> => {
      return apiClient<EnvironmentInfo[]>('/environments');
    },
    staleTime: 300_000,
  });
}

export function usePromote() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ scanId, environment }: { scanId: string; environment: string }) => {
      return apiClient(`/scans/${scanId}/promote`, {
        method: 'POST',
        body: { environment },
      });
    },
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ['provenance', variables.scanId] });
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast({ title: `Promoted to ${variables.environment}`, variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Promotion failed', description: err.message, variant: 'error' });
    },
  });
}
