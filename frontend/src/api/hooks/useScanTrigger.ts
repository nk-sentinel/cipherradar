import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client';
import { useToast } from '@/lib/use-toast';

export interface ScanTriggerParams {
  projectId: string;
  sourceType: 'repository' | 'container' | 'artifact';
  branch?: string;
  policyId?: string;
  containerTag?: string;
  artifactVersion?: string;
}

interface ScanTriggerResponse {
  status: string;
  scanId: string;
}

export function useScanTrigger() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (params: ScanTriggerParams): Promise<ScanTriggerResponse> => {
      return apiClient<ScanTriggerResponse>(`/projects/${params.projectId}/scans/trigger`, {
        method: 'POST',
        body: {
          sourceType: params.sourceType,
          branch: params.branch,
          policyId: params.policyId,
          containerTag: params.containerTag,
          artifactVersion: params.artifactVersion,
        },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast({ title: 'Scan triggered', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to trigger scan', description: err.message, variant: 'error' });
    },
  });
}
