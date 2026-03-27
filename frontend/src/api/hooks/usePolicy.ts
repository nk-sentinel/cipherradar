import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PolicyScope = 'org' | 'group' | 'project';
export type PolicySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface PolicyRuleConfig {
  id: string;
  severity: PolicySeverity;
  enabled: boolean;
  locked: boolean;
  scope: PolicyScope;
  inheritedFrom: string | null;
}

export interface PolicyConfig {
  rules: PolicyRuleConfig[];
}

export interface SavePolicyPayload {
  rules: PolicyRuleConfig[];
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch the current policy configuration.
 * Real API endpoint: GET /api/v1/admin/policy
 */
export function usePolicy() {
  return useQuery<PolicyConfig>({
    queryKey: ['admin', 'policy'],
    queryFn: async () => {
      return apiClient<PolicyConfig>('/admin/policy');
    },
    staleTime: 60_000,
  });
}

/**
 * Save policy configuration changes.
 * Real API endpoint: PUT /api/v1/admin/policy
 */
export function useSavePolicy() {
  const queryClient = useQueryClient();
  return useMutation<PolicyConfig, Error, SavePolicyPayload>({
    mutationFn: async (payload) => {
      return apiClient<PolicyConfig>('/admin/policy', {
        method: 'PUT',
        body: payload,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'policy'] });
    },
  });
}
