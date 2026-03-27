import { describe, it, expect } from 'vitest';

describe('useLLMConfig hooks', () => {
  it('exports useLLMConfig hook', async () => {
    const mod = await import('@/api/hooks/useLLMConfig');
    expect(typeof mod.useLLMConfig).toBe('function');
  });

  it('exports useSaveLLMConfig hook', async () => {
    const mod = await import('@/api/hooks/useLLMConfig');
    expect(typeof mod.useSaveLLMConfig).toBe('function');
  });

  it('exports useTestLLMConnection hook', async () => {
    const mod = await import('@/api/hooks/useLLMConfig');
    expect(typeof mod.useTestLLMConnection).toBe('function');
  });

  it('LLM_PROVIDER_DEFAULTS has entries for all providers', async () => {
    const mod = await import('@/api/hooks/useLLMConfig');
    expect(mod.LLM_PROVIDER_DEFAULTS.anthropic).toBeDefined();
    expect(mod.LLM_PROVIDER_DEFAULTS.openai).toBeDefined();
    expect(mod.LLM_PROVIDER_DEFAULTS.ollama).toBeDefined();
    expect(mod.LLM_PROVIDER_DEFAULTS.custom).toBeDefined();
    expect(mod.LLM_PROVIDER_DEFAULTS.disabled).toBeDefined();
  });

  it('anthropic default URL is correct', async () => {
    const mod = await import('@/api/hooks/useLLMConfig');
    expect(mod.LLM_PROVIDER_DEFAULTS.anthropic.url).toBe('https://api.anthropic.com');
  });

  it('openai default model is gpt-4o', async () => {
    const mod = await import('@/api/hooks/useLLMConfig');
    expect(mod.LLM_PROVIDER_DEFAULTS.openai.model).toBe('gpt-4o');
  });
});

describe('LLMConfig page', () => {
  it('exports the page component', async () => {
    const mod = await import('@/pages/admin/LLMConfig');
    expect(typeof mod.LLMConfig).toBe('function');
  });
});
