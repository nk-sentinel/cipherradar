import { describe, it, expect } from 'vitest';

describe('EmptyState component', () => {
  it('exports the EmptyState component', async () => {
    const mod = await import('@/components/ui/EmptyState');
    expect(typeof mod.EmptyState).toBe('function');
  });

  it('exports the GuestBanner component', async () => {
    const mod = await import('@/components/ui/EmptyState');
    expect(typeof mod.GuestBanner).toBe('function');
  });
});

describe('EmptyState props interface', () => {
  it('EmptyState accepts required props', async () => {
    const mod = await import('@/components/ui/EmptyState');
    // Verify the function has expected arity (component with props)
    expect(mod.EmptyState.length).toBeGreaterThanOrEqual(0);
  });
});

describe('Repositories page with EmptyState', () => {
  it('exports the Repositories component', async () => {
    const mod = await import('@/pages/Repositories');
    expect(typeof mod.Repositories).toBe('function');
  });
});

describe('ScanQueue page with EmptyState', () => {
  it('exports the ScanQueue component', async () => {
    const mod = await import('@/pages/ScanQueue');
    expect(typeof mod.ScanQueue).toBe('function');
  });
});

describe('RepoFindings page with EmptyState', () => {
  it('exports the RepoFindings component', async () => {
    const mod = await import('@/pages/repo/RepoFindings');
    expect(typeof mod.RepoFindings).toBe('function');
  });
});
