import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client';

interface HealthResponse {
  status: string;
  version: string;
}

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => apiClient<HealthResponse>('/health'),
    staleTime: 60_000,
  });
}
