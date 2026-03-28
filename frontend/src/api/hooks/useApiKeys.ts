import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  createdAt: string;
  lastUsed: string | null;
  status: 'active' | 'revoked';
}

interface CreateApiKeyParams {
  name: string;
  expiresInDays: number | null;
  scopes: string[];
}

interface CreateApiKeyResponse {
  id: string;
  name: string;
  prefix: string;
  rawKey: string;
  scopes: string[];
  createdAt: string;
  expiresAt: string | null;
}

/**
 * Fetch current user's API keys.
 * Real API endpoint: GET /api/v1/auth/api-keys
 */
export function useMyApiKeys() {
  return useQuery({
    queryKey: ['auth', 'api-keys'],
    queryFn: async () => {
      const data = await apiClient<ApiKey[] | { items: ApiKey[] }>('/auth/api-keys');
      return Array.isArray(data) ? data : (data.items ?? []);
    },
    staleTime: 30_000,
  });
}

/**
 * Create a new API key.
 * Real API endpoint: POST /api/v1/auth/api-keys
 */
export function useCreateApiKey() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (params: CreateApiKeyParams) => {
      return apiClient<CreateApiKeyResponse>('/auth/api-keys', {
        method: 'POST',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['auth', 'api-keys'] });
    },
    onError: (err) => {
      toast({ title: 'Failed to create API key', description: err.message, variant: 'error' });
    },
  });
}

/**
 * Revoke an API key.
 * Real API endpoint: DELETE /api/v1/auth/api-keys/:keyId
 */
export function useRevokeApiKey() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (keyId: string) => {
      return apiClient(`/auth/api-keys/${keyId}`, {
        method: 'DELETE',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['auth', 'api-keys'] });
      toast({ title: 'API key revoked', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to revoke API key', description: err.message, variant: 'error' });
    },
  });
}
