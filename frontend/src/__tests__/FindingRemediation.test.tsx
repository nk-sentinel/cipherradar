import { describe, it, expect } from 'vitest';

describe('ConsentModal component', () => {
  it('exports the ConsentModal component', async () => {
    const mod = await import('@/components/findings/ConsentModal');
    expect(typeof mod.ConsentModal).toBe('function');
  });
});

describe('RemediationResult component', () => {
  it('exports the RemediationResult component', async () => {
    const mod = await import('@/components/findings/RemediationResult');
    expect(typeof mod.RemediationResult).toBe('function');
  });
});

describe('FindingRemediation page', () => {
  it('exports the FindingRemediation component', async () => {
    const mod = await import('@/pages/repo/FindingRemediation');
    expect(typeof mod.FindingRemediation).toBe('function');
  });
});

describe('useRemediation hooks', () => {
  it('exports useRemediation hook', async () => {
    const mod = await import('@/api/hooks/useRemediation');
    expect(typeof mod.useRemediation).toBe('function');
  });

  it('exports useRequestRemediation hook', async () => {
    const mod = await import('@/api/hooks/useRemediation');
    expect(typeof mod.useRequestRemediation).toBe('function');
  });
});

describe('Remediation mock data', () => {
  it('returns remediation for known finding', async () => {
    const mod = await import('@/mocks/data/remediation');
    const rem = mod.getRemediationForFinding('f-002');
    expect(rem).toBeDefined();
    expect(rem!.confidence).toBe('high');
    expect(rem!.provider).toBe('anthropic');
    expect(rem!.diff.originalCode).toContain('md5');
    expect(rem!.diff.fixedCode).toContain('sha256');
  });

  it('returns undefined for unknown finding', async () => {
    const mod = await import('@/mocks/data/remediation');
    const rem = mod.getRemediationForFinding('non-existent');
    expect(rem).toBeUndefined();
  });
});
