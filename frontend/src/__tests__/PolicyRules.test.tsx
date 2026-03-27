import { describe, it, expect } from 'vitest';

describe('usePolicy hooks', () => {
  it('exports usePolicy hook', async () => {
    const mod = await import('@/api/hooks/usePolicy');
    expect(typeof mod.usePolicy).toBe('function');
  });

  it('exports useSavePolicy hook', async () => {
    const mod = await import('@/api/hooks/usePolicy');
    expect(typeof mod.useSavePolicy).toBe('function');
  });
});

describe('PolicyRules page', () => {
  it('exports the PolicyRules component', async () => {
    const mod = await import('@/pages/PolicyRules');
    expect(typeof mod.PolicyRules).toBe('function');
  });
});

describe('PolicyRules severity options', () => {
  it('SEVERITY_OPTIONS contains expected values', async () => {
    const mod = await import('@/pages/PolicyRules');
    expect(mod.SEVERITY_OPTIONS).toBeDefined();
    expect(mod.SEVERITY_OPTIONS.length).toBeGreaterThanOrEqual(3);
    const values = mod.SEVERITY_OPTIONS.map((o: { value: string }) => o.value);
    expect(values).toContain('critical');
    expect(values).toContain('high');
    expect(values).toContain('medium');
  });
});

describe('PolicyRules scope options', () => {
  it('SCOPE_OPTIONS contains org, group, project', async () => {
    const mod = await import('@/pages/PolicyRules');
    expect(mod.SCOPE_OPTIONS).toBeDefined();
    const values = mod.SCOPE_OPTIONS.map((o: { value: string }) => o.value);
    expect(values).toContain('org');
    expect(values).toContain('group');
    expect(values).toContain('project');
  });
});
