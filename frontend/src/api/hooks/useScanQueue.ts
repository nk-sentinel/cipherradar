import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client';

export interface ScanQueueItem {
  id: string;
  projectName: string;
  projectId: string;
  triggerType: 'manual' | 'schedule' | 'webhook' | 'push';
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  startedAt: string;
  duration: string | null;
  triggeredBy: string;
}

interface ScanQueueResponse {
  items: ScanQueueItem[];
  total: number;
  page: number;
  perPage: number;
}

interface ScanQueueFilters {
  status?: string;
  projectId?: string;
  triggerType?: string;
  page?: number;
  perPage?: number;
}

export function useScanQueue(filters: ScanQueueFilters = {}) {
  const { status, projectId, triggerType, page = 1, perPage = 25 } = filters;

  const hasRunning = true; // We want auto-refresh when there are running scans

  return useQuery<ScanQueueResponse>({
    queryKey: ['scan-queue', status, projectId, triggerType, page, perPage],
    queryFn: async (): Promise<ScanQueueResponse> => {
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (projectId) params.set('projectId', projectId);
      if (triggerType) params.set('triggerType', triggerType);
      params.set('page', String(page));
      params.set('perPage', String(perPage));

      return apiClient<ScanQueueResponse>(`/scans?${params.toString()}`);
    },
    staleTime: 10_000,
    refetchInterval: hasRunning ? 5_000 : false,
  });
}
