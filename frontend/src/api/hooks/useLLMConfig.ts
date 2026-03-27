import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LLMProviderType = 'anthropic' | 'openai' | 'ollama' | 'custom' | 'disabled';

export interface LLMConfig {
  provider: LLMProviderType;
  apiUrl: string;
  apiKey: string;
  model: string;
  temperature: number;
  maxTokens: number;
  privacy: LLMPrivacySettings;
  customInstructions: string;
}

export interface LLMPrivacySettings {
  consentRequired: boolean;
  stripComments: boolean;
  anonymizeVariables: boolean;
}

export interface TestLLMConnectionResult {
  success: boolean;
  message: string;
  latencyMs: number;
  model: string;
}

export const LLM_PROVIDER_DEFAULTS: Record<LLMProviderType, { url: string; model: string }> = {
  anthropic: { url: 'https://api.anthropic.com', model: 'claude-sonnet-4-20250514' },
  openai: { url: 'https://api.openai.com', model: 'gpt-4o' },
  ollama: { url: 'http://localhost:11434', model: 'llama3' },
  custom: { url: '', model: '' },
  disabled: { url: '', model: '' },
};

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch current LLM configuration.
 * Real API endpoint: GET /api/v1/admin/llm-config
 */
export function useLLMConfig() {
  return useQuery<LLMConfig>({
    queryKey: ['admin', 'llm-config'],
    queryFn: async () => {
      return apiClient<LLMConfig>('/admin/llm-config');
    },
    staleTime: 60_000,
  });
}

/**
 * Save LLM configuration.
 * Real API endpoint: PUT /api/v1/admin/llm-config
 */
export function useSaveLLMConfig() {
  const queryClient = useQueryClient();
  return useMutation<LLMConfig, Error, LLMConfig>({
    mutationFn: async (config) => {
      return apiClient<LLMConfig>('/admin/llm-config', {
        method: 'PUT',
        body: config,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'llm-config'] });
    },
  });
}

/**
 * Test LLM connection.
 * Real API endpoint: POST /api/v1/admin/llm-config/test
 */
export function useTestLLMConnection() {
  return useMutation<TestLLMConnectionResult, Error, Partial<LLMConfig>>({
    mutationFn: async (config) => {
      return apiClient<TestLLMConnectionResult>('/admin/llm-config/test', {
        method: 'POST',
        body: config,
      });
    },
  });
}
