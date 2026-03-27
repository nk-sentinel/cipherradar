import { describe, it, expect } from 'vitest';

describe('useCustomRules hooks', () => {
  it('exports useRules hook', async () => {
    const mod = await import('@/api/hooks/useCustomRules');
    expect(typeof mod.useRules).toBe('function');
  });

  it('exports useCreateRule hook', async () => {
    const mod = await import('@/api/hooks/useCustomRules');
    expect(typeof mod.useCreateRule).toBe('function');
  });

  it('exports useValidateRule hook', async () => {
    const mod = await import('@/api/hooks/useCustomRules');
    expect(typeof mod.useValidateRule).toBe('function');
  });

  it('exports useDryRunRule hook', async () => {
    const mod = await import('@/api/hooks/useCustomRules');
    expect(typeof mod.useDryRunRule).toBe('function');
  });

  it('exports useForkRule hook', async () => {
    const mod = await import('@/api/hooks/useCustomRules');
    expect(typeof mod.useForkRule).toBe('function');
  });
});

describe('CustomRulesPanel component', () => {
  it('exports the CustomRulesPanel component', async () => {
    const mod = await import('@/components/rules/CustomRulesPanel');
    expect(typeof mod.CustomRulesPanel).toBe('function');
  });
});

describe('CustomRulesPanel constants', () => {
  it('exports LANGUAGE_OPTIONS', async () => {
    const mod = await import('@/components/rules/CustomRulesPanel');
    expect(mod.LANGUAGE_OPTIONS).toBeDefined();
    expect(mod.LANGUAGE_OPTIONS.length).toBeGreaterThan(0);
  });

  it('exports SOURCE_OPTIONS', async () => {
    const mod = await import('@/components/rules/CustomRulesPanel');
    expect(mod.SOURCE_OPTIONS).toBeDefined();
    expect(mod.SOURCE_OPTIONS.length).toBe(3); // All, Built-in, Custom
  });
});
