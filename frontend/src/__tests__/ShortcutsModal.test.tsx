import { describe, it, expect } from 'vitest';

describe('ShortcutsModal component', () => {
  it('exports the ShortcutsModal component', async () => {
    const mod = await import('@/components/layout/ShortcutsModal');
    expect(typeof mod.ShortcutsModal).toBe('function');
  });

  it('exports SHORTCUTS constant with at least 3 entries', async () => {
    const mod = await import('@/components/layout/ShortcutsModal');
    expect(Array.isArray(mod.SHORTCUTS)).toBe(true);
    expect(mod.SHORTCUTS.length).toBeGreaterThanOrEqual(3);
  });

  it('SHORTCUTS contains Ctrl+K for Search', async () => {
    const mod = await import('@/components/layout/ShortcutsModal');
    const searchShortcut = mod.SHORTCUTS.find(
      (s: { keys: string; action: string }) => s.keys === 'Ctrl+K',
    );
    expect(searchShortcut).toBeDefined();
    expect(searchShortcut!.action).toBe('Search');
  });

  it('SHORTCUTS contains Ctrl+B for Toggle sidebar', async () => {
    const mod = await import('@/components/layout/ShortcutsModal');
    const sidebarShortcut = mod.SHORTCUTS.find(
      (s: { keys: string; action: string }) => s.keys === 'Ctrl+B',
    );
    expect(sidebarShortcut).toBeDefined();
    expect(sidebarShortcut!.action).toBe('Toggle sidebar');
  });

  it('SHORTCUTS contains ? for Show this modal', async () => {
    const mod = await import('@/components/layout/ShortcutsModal');
    const helpShortcut = mod.SHORTCUTS.find(
      (s: { keys: string; action: string }) => s.keys === '?',
    );
    expect(helpShortcut).toBeDefined();
    expect(helpShortcut!.action).toBe('Show this modal');
  });
});

describe('AvatarDropdown integration', () => {
  it('exports the AvatarDropdown component', async () => {
    const mod = await import('@/components/layout/AvatarDropdown');
    expect(typeof mod.AvatarDropdown).toBe('function');
  });
});
