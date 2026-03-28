import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';

export interface AdminApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  owner: string;
  scopes: string[];
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  status: 'active' | 'revoked' | 'expired';
}

interface AdminApiKeysResponse {
  items: AdminApiKey[];
  total: number;
}

/**
 * Fetch all org API keys (admin view).
 * Real API endpoint: GET /api/v1/admin/api-keys
 */
export function useAdminApiKeys() {
  return useQuery({
    queryKey: ['admin-api-keys'],
    queryFn: async () => {
      const data = await apiClient<AdminApiKeysResponse | AdminApiKey[]>('/admin/api-keys');
      if (Array.isArray(data)) return { items: data, total: data.length };
      return { items: data.items ?? [], total: data.total ?? 0 };
    },
    staleTime: 30_000,
  });
}

/**
 * Revoke an API key as admin.
 * Real API endpoint: DELETE /api/v1/admin/api-keys/:keyId
 */
export function useAdminRevokeApiKey() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (keyId: string) => {
      return apiClient(`/admin/api-keys/${keyId}`, { method: 'DELETE' });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin-api-keys'] });
      toast({ title: 'API key revoked', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to revoke API key', description: err.message, variant: 'error' });
    },
  });
}
