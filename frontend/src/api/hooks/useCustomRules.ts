import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CustomRule {
  id: string;
  name: string;
  language: string;
  severity: string;
  source: 'built-in' | 'custom';
  enabled: boolean;
  description: string;
  yaml?: string;
}

export interface ValidateRuleResult {
  valid: boolean;
  errors: string[];
}

export interface DryRunResult {
  matchCount: number;
  sampleMatches: { file: string; line: number; snippet: string }[];
}

export interface ForkRuleResult {
  id: string;
  name: string;
  source: 'custom';
  enabled: boolean;
  yaml: string;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch all rules (built-in + custom) with optional filters.
 * Real API endpoint: GET /api/v1/admin/rules?source=...&language=...&severity=...&search=...
 */
export function useRules(filters: {
  source?: string;
  language?: string;
  severity?: string;
  search?: string;
} = {}) {
  const params = new URLSearchParams();
  if (filters.source) params.set('source', filters.source);
  if (filters.language) params.set('language', filters.language);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.search) params.set('search', filters.search);
  const qs = params.toString();

  return useQuery<CustomRule[]>({
    queryKey: ['admin', 'rules', filters],
    queryFn: async () => {
      return apiClient<CustomRule[]>(`/admin/rules${qs ? `?${qs}` : ''}`);
    },
    staleTime: 30_000,
  });
}

/**
 * Upload a new custom rule.
 * Real API endpoint: POST /api/v1/admin/rules
 */
export function useCreateRule() {
  const queryClient = useQueryClient();
  return useMutation<CustomRule, Error, { yaml: string; name: string; language: string; severity: string }>({
    mutationFn: async (payload) => {
      return apiClient<CustomRule>('/admin/rules', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'rules'] });
    },
  });
}

/**
 * Validate a rule YAML.
 * Real API endpoint: POST /api/v1/admin/rules/validate
 */
export function useValidateRule() {
  return useMutation<ValidateRuleResult, Error, { yaml: string }>({
    mutationFn: async (payload) => {
      return apiClient<ValidateRuleResult>('/admin/rules/validate', {
        method: 'POST',
        body: payload,
      });
    },
  });
}

/**
 * Dry-run a rule against the codebase.
 * Real API endpoint: POST /api/v1/admin/rules/dry-run
 */
export function useDryRunRule() {
  return useMutation<DryRunResult, Error, { yaml: string }>({
    mutationFn: async (payload) => {
      return apiClient<DryRunResult>('/admin/rules/dry-run', {
        method: 'POST',
        body: payload,
      });
    },
  });
}

/**
 * Fork a built-in rule to create a custom copy.
 * Real API endpoint: POST /api/v1/admin/rules/:ruleId/fork
 */
export function useForkRule() {
  const queryClient = useQueryClient();
  return useMutation<ForkRuleResult, Error, { ruleId: string }>({
    mutationFn: async ({ ruleId }) => {
      return apiClient<ForkRuleResult>(`/admin/rules/${ruleId}/fork`, {
        method: 'POST',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'rules'] });
    },
  });
}
