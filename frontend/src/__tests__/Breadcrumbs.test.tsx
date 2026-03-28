import { describe, it, expect } from 'vitest';

describe('Breadcrumbs component', () => {
  it('exports the Breadcrumbs component', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    expect(typeof mod.Breadcrumbs).toBe('function');
  });
});

describe('useBreadcrumbs hook', () => {
  it('exports useBreadcrumbs hook', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    expect(typeof mod.useBreadcrumbs).toBe('function');
  });
});

describe('Breadcrumb segment generation', () => {
  it('exports buildBreadcrumbs utility', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    expect(typeof mod.buildBreadcrumbs).toBe('function');
  });

  it('returns Dashboard crumb for root path (no org)', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    const segments = mod.buildBreadcrumbs('/', {});
    expect(segments).toHaveLength(1);
    expect(segments[0].label).toBe('Dashboard');
  });

  it('returns Org > Dashboard crumbs for root path (with org)', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    const segments = mod.buildBreadcrumbs('/', { orgName: 'nk-sentinel' });
    expect(segments).toHaveLength(2);
    expect(segments[0].label).toBe('nk-sentinel');
    expect(segments[1].label).toBe('Dashboard');
  });

  it('returns Projects crumb for /repos path', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    const segments = mod.buildBreadcrumbs('/repos', {});
    expect(segments).toHaveLength(1);
    expect(segments[0].label).toBe('Projects');
    expect(segments[0].to).toBe('/repos');
  });

  it('returns Org > Repo > Tab crumbs for project sub-tab', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    const segments = mod.buildBreadcrumbs('/repos/repo-1/findings', {
      repoId: 'repo-1',
      repoName: 'payment-service',
      orgName: 'nk-sentinel',
    });
    expect(segments.length).toBeGreaterThanOrEqual(3);
    expect(segments[0].label).toBe('nk-sentinel');
    expect(segments[1].label).toBe('payment-service');
    expect(segments[2].label).toBe('Findings');
  });

  it('falls back to repoId when repoName is not provided', async () => {
    const mod = await import('@/components/layout/Breadcrumbs');
    const segments = mod.buildBreadcrumbs('/repos/repo-1/overview', {
      repoId: 'repo-1',
    });
    expect(segments.some((s: { label: string }) => s.label === 'repo-1')).toBe(true);
  });
});
