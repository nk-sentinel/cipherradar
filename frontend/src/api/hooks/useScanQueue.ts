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
  environment: string | null;
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

  return useQuery<ScanQueueResponse>({
    queryKey: ['scan-queue', status, projectId, triggerType, page, perPage],
    queryFn: async (): Promise<ScanQueueResponse> => {
      try {
        const params = new URLSearchParams();
        if (status) params.set('status', status);
        if (projectId) params.set('projectId', projectId);
        if (triggerType) params.set('triggerType', triggerType);
        params.set('page', String(page));
        params.set('perPage', String(perPage));

        const data = await apiClient<ScanQueueResponse | ScanQueueItem[]>(`/scans?${params.toString()}`);
        if (Array.isArray(data)) {
          return { items: data, total: data.length, page, perPage };
        }
        return data ?? { items: [], total: 0, page, perPage };
      } catch {
        return { items: [], total: 0, page, perPage };
      }
    },
    retry: 1,
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
}
