import { describe, it, expect } from 'vitest';

describe('Sidebar component', () => {
  it('exports the Sidebar component', async () => {
    const mod = await import('@/components/layout/Sidebar');
    expect(typeof mod.Sidebar).toBe('function');
  });
});

describe('Sidebar uses Lucide React icons', () => {
  it('imports Lucide icons instead of Unicode characters', async () => {
    // Read the source to verify no Unicode icon strings remain
    const mod = await import('@/components/layout/Sidebar');
    expect(mod.Sidebar).toBeDefined();
    // The NAV_SECTIONS should be exported for testing
    expect(mod.NAV_SECTIONS).toBeDefined();
    expect(Array.isArray(mod.NAV_SECTIONS)).toBe(true);
  });

  it('has no Unicode icon strings in nav items', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const unicodeIcons = ['\u25A0', '\u26B1', '\u2630', '\u25B6', '\u269B', '\u2713', '\u2611', '\u2B21', '\u2B50', '\u0394', '\u21C4', '\u2699', '\u263A', '\u26A1', '\u2637', '\u2B22', '\u2709'];
    for (const section of mod.NAV_SECTIONS) {
      for (const item of section.items) {
        // icon should be a React component (function), not a string
        expect(typeof item.icon).toBe('function');
        expect(unicodeIcons).not.toContain(item.icon);
      }
    }
  });

  it('Dashboard item uses LayoutDashboard icon', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const { LayoutDashboard } = await import('lucide-react');
    const dashboardItem = mod.NAV_SECTIONS
      .flatMap((s: { items: Array<{ label: string; icon: unknown }> }) => s.items)
      .find((i: { label: string }) => i.label === 'Dashboard');
    expect(dashboardItem).toBeDefined();
    expect(dashboardItem!.icon).toBe(LayoutDashboard);
  });

  it('Projects item uses FolderKanban icon', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const { FolderKanban } = await import('lucide-react');
    const item = mod.NAV_SECTIONS
      .flatMap((s: { items: Array<{ label: string; icon: unknown }> }) => s.items)
      .find((i: { label: string }) => i.label === 'Projects');
    expect(item).toBeDefined();
    expect(item!.icon).toBe(FolderKanban);
  });

  it('Scans item uses Zap icon', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const { Zap } = await import('lucide-react');
    const item = mod.NAV_SECTIONS
      .flatMap((s: { items: Array<{ label: string; icon: unknown }> }) => s.items)
      .find((i: { label: string }) => i.label === 'Scans');
    expect(item).toBeDefined();
    expect(item!.icon).toBe(Zap);
  });

  it('Findings item uses Flag icon', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const { Flag } = await import('lucide-react');
    const item = mod.NAV_SECTIONS
      .flatMap((s: { items: Array<{ label: string; icon: unknown }> }) => s.items)
      .find((i: { label: string }) => i.label === 'Findings');
    expect(item).toBeDefined();
    expect(item!.icon).toBe(Flag);
  });

  it('Portfolio Compliance item uses Shield icon', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const { Shield } = await import('lucide-react');
    const item = mod.NAV_SECTIONS
      .flatMap((s: { items: Array<{ label: string; icon: unknown }> }) => s.items)
      .find((i: { label: string }) => i.label === 'Portfolio Compliance');
    expect(item).toBeDefined();
    expect(item!.icon).toBe(Shield);
  });

  it('Pending Requests item uses MessageSquare icon', async () => {
    const mod = await import('@/components/layout/Sidebar');
    const { MessageSquare } = await import('lucide-react');
    const item = mod.NAV_SECTIONS
      .flatMap((s: { items: Array<{ label: string; icon: unknown }> }) => s.items)
      .find((i: { label: string }) => i.label === 'Pending Requests');
    expect(item).toBeDefined();
    expect(item!.icon).toBe(MessageSquare);
  });
});

describe('Sidebar project tree', () => {
  it('exports ProjectTree component', async () => {
    const mod = await import('@/components/layout/ProjectTree');
    expect(typeof mod.ProjectTree).toBe('function');
  });
});

describe('Sidebar customizable labels (D4)', () => {
  it('exports useEntityLabels hook', async () => {
    const mod = await import('@/components/layout/ProjectTree');
    expect(typeof mod.useEntityLabels).toBe('function');
  });

  it('defaults to Group/Project labels', async () => {
    const mod = await import('@/components/layout/ProjectTree');
    const labels = mod.DEFAULT_ENTITY_LABELS;
    expect(labels).toBeDefined();
    expect(labels.group).toBe('Group');
    expect(labels.project).toBe('Project');
  });
});
