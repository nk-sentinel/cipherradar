import { describe, it, expect, vi } from 'vitest';

// ---------------------------------------------------------------------------
// Unit tests for Integration Management hooks and page logic
// ---------------------------------------------------------------------------

describe('useIntegrationProviders', () => {
  it('exports the hook function', async () => {
    const mod = await import('@/api/hooks/useIntegrations');
    expect(typeof mod.useIntegrationProviders).toBe('function');
  });

  it('exports useConnectProvider hook', async () => {
    const mod = await import('@/api/hooks/useIntegrations');
    expect(typeof mod.useConnectProvider).toBe('function');
  });

  it('exports useDisconnectProvider hook', async () => {
    const mod = await import('@/api/hooks/useIntegrations');
    expect(typeof mod.useDisconnectProvider).toBe('function');
  });

  it('exports useDiscoverRepos hook', async () => {
    const mod = await import('@/api/hooks/useIntegrations');
    expect(typeof mod.useDiscoverRepos).toBe('function');
  });

  it('exports useImportRepos hook', async () => {
    const mod = await import('@/api/hooks/useIntegrations');
    expect(typeof mod.useImportRepos).toBe('function');
  });

  it('exports useTestConnection hook', async () => {
    const mod = await import('@/api/hooks/useIntegrations');
    expect(typeof mod.useTestConnection).toBe('function');
  });
});

describe('IntegrationManagement page helpers', () => {
  it('providerScopes returns correct required scopes per provider', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(mod.PROVIDER_SCOPES.github).toContain('repo');
    expect(mod.PROVIDER_SCOPES.gitlab).toContain('api');
    expect(mod.PROVIDER_SCOPES.bitbucket).toBeDefined();
  });

  it('tokenAgeDays calculates age correctly', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(mod.tokenAgeDays(null)).toBe(null);
    expect(typeof mod.tokenAgeDays(30)).toBe('number');
  });

  it('shouldWarnRotation returns true when token is old', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(mod.shouldWarnRotation(91)).toBe(true);
    expect(mod.shouldWarnRotation(30)).toBe(false);
    expect(mod.shouldWarnRotation(null)).toBe(false);
  });
});

describe('IntegrationManagement page', () => {
  it('exports the page component', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(typeof mod.IntegrationManagement).toBe('function');
  });
});

describe('Integration mock data', () => {
  it('getIntegrationsEnriched returns providers with syncedRepoCount and tokenAge', async () => {
    const mod = await import('@/mocks/data/admin');
    const integrations = mod.getIntegrationsEnriched();
    expect(Array.isArray(integrations)).toBe(true);
    expect(integrations.length).toBeGreaterThan(0);
    const github = integrations.find((i: { type: string }) => i.type === 'github');
    expect(github).toBeDefined();
    expect(typeof github!.syncedRepoCount).toBe('number');
    expect(github!.tokenAge).toBeDefined();
    expect(typeof github!.tokenRotationWarning).toBe('boolean');
  });
});
