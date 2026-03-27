import { describe, it, expect } from 'vitest';

describe('RepoLayout tab consolidation', () => {
  it('exports RepoLayout component', async () => {
    const mod = await import('@/pages/repo/RepoLayout');
    expect(typeof mod.RepoLayout).toBe('function');
  });

  it('defines exactly 6 consolidated tabs', async () => {
    const mod = await import('@/pages/repo/RepoLayout');
    expect(mod.CONSOLIDATED_TABS).toBeDefined();
    expect(mod.CONSOLIDATED_TABS).toHaveLength(6);
  });

  it('has Overview, Findings, Compliance, Dependencies, Scans, Settings tabs', async () => {
    const mod = await import('@/pages/repo/RepoLayout');
    const labels = mod.CONSOLIDATED_TABS.map((t: { label: string }) => t.label);
    expect(labels).toEqual([
      'Overview',
      'Findings',
      'Compliance',
      'Dependencies',
      'Scans',
      'Settings',
    ]);
  });

  it('Compliance tab path is compliance', async () => {
    const mod = await import('@/pages/repo/RepoLayout');
    const complianceTab = mod.CONSOLIDATED_TABS.find(
      (t: { label: string }) => t.label === 'Compliance',
    );
    expect(complianceTab).toBeDefined();
    expect(complianceTab!.path).toBe('compliance');
  });

  it('Dependencies tab path is dependencies', async () => {
    const mod = await import('@/pages/repo/RepoLayout');
    const depsTab = mod.CONSOLIDATED_TABS.find(
      (t: { label: string }) => t.label === 'Dependencies',
    );
    expect(depsTab).toBeDefined();
    expect(depsTab!.path).toBe('dependencies');
  });
});

describe('RepoComplianceUnified merges quantum readiness into compliance', () => {
  it('exports RepoComplianceUnified component', async () => {
    const mod = await import('@/pages/repo/RepoComplianceUnified');
    expect(typeof mod.RepoComplianceUnified).toBe('function');
  });
});

describe('RepoDependencies merges SBOM into dependencies view', () => {
  it('exports RepoDependencies component', async () => {
    const mod = await import('@/pages/repo/RepoDependencies');
    expect(typeof mod.RepoDependencies).toBe('function');
  });
});

describe('RepoSettings consolidates settings tabs', () => {
  it('exports RepoSettings component', async () => {
    const mod = await import('@/pages/repo/RepoSettings');
    expect(typeof mod.RepoSettings).toBe('function');
  });
});
