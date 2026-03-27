import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ProviderType = 'github' | 'gitlab' | 'bitbucket' | 'jira' | 'teams';
export type IntegrationStatus = 'connected' | 'disconnected' | 'error';

export interface IntegrationProvider {
  id: string;
  type: ProviderType;
  label: string;
  status: IntegrationStatus;
  connectedAt: string | null;
  detail: string | null;
  syncedRepoCount: number;
  tokenAge: number | null;
  tokenRotationWarning: boolean;
}

export interface ConnectProviderPayload {
  type: ProviderType;
  baseUrl: string;
  token: string;
}

export interface TestConnectionResult {
  success: boolean;
  message: string;
  latencyMs: number;
}

export interface DiscoveredRepo {
  id: string;
  name: string;
  fullName: string;
  language: string | null;
  defaultBranch: string;
  lastPush: string;
  private: boolean;
  alreadyImported: boolean;
}

export interface ImportReposPayload {
  providerType: ProviderType;
  repoIds: string[];
  groupId: string | null;
  autoScan: boolean;
}

export interface ImportReposResult {
  imported: number;
  failed: number;
  errors: string[];
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch all integration providers with enriched data (synced repo count, token age).
 * Real API endpoint: GET /api/v1/admin/integrations
 */
export function useIntegrationProviders() {
  return useQuery<IntegrationProvider[]>({
    queryKey: ['admin', 'integration-providers'],
    queryFn: async () => {
      return apiClient<IntegrationProvider[]>('/admin/integrations');
    },
    staleTime: 30_000,
  });
}

/**
 * Connect a provider via PAT (personal access token).
 * Real API endpoint: POST /api/v1/admin/integrations/connect
 */
export function useConnectProvider() {
  const queryClient = useQueryClient();
  return useMutation<IntegrationProvider, Error, ConnectProviderPayload>({
    mutationFn: async (payload) => {
      return apiClient<IntegrationProvider>('/admin/integrations/connect', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'integration-providers'] });
    },
  });
}

/**
 * Disconnect a provider.
 * Real API endpoint: POST /api/v1/admin/integrations/:providerId/disconnect
 */
export function useDisconnectProvider() {
  const queryClient = useQueryClient();
  return useMutation<void, Error, { providerId: string }>({
    mutationFn: async ({ providerId }) => {
      return apiClient<void>(`/admin/integrations/${providerId}/disconnect`, {
        method: 'POST',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'integration-providers'] });
    },
  });
}

/**
 * Test connection for a provider.
 * Real API endpoint: POST /api/v1/admin/integrations/:providerId/test
 */
export function useTestConnection() {
  return useMutation<TestConnectionResult, Error, { providerId: string }>({
    mutationFn: async ({ providerId }) => {
      return apiClient<TestConnectionResult>(
        `/admin/integrations/${providerId}/test`,
        { method: 'POST' },
      );
    },
  });
}

/**
 * Discover repos available for import from a connected provider.
 * Real API endpoint: GET /api/v1/admin/integrations/:providerId/repos?search=...
 */
export function useDiscoverRepos(providerId: string | null, search: string) {
  return useQuery<DiscoveredRepo[]>({
    queryKey: ['admin', 'discover-repos', providerId, search],
    queryFn: async () => {
      const params = search ? `?search=${encodeURIComponent(search)}` : '';
      return apiClient<DiscoveredRepo[]>(
        `/admin/integrations/${providerId!}/repos${params}`,
      );
    },
    staleTime: 30_000,
    enabled: !!providerId,
  });
}

/**
 * Import selected repos from a provider.
 * Real API endpoint: POST /api/v1/admin/integrations/import
 */
export function useImportRepos() {
  const queryClient = useQueryClient();
  return useMutation<ImportReposResult, Error, ImportReposPayload>({
    mutationFn: async (payload) => {
      return apiClient<ImportReposResult>('/admin/integrations/import', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'integration-providers'] });
      void queryClient.invalidateQueries({ queryKey: ['admin', 'discover-repos'] });
    },
  });
}
