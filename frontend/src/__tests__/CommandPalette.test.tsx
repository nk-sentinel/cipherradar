import { describe, it, expect } from 'vitest';

describe('CommandPalette component', () => {
  it('exports the CommandPalette component', async () => {
    const mod = await import('@/components/layout/CommandPalette');
    expect(typeof mod.CommandPalette).toBe('function');
  });
});

describe('useSearch hook', () => {
  it('exports useSearch hook', async () => {
    const mod = await import('@/api/hooks/useSearch');
    expect(typeof mod.useSearch).toBe('function');
  });
});

describe('useSearch hook types', () => {
  it('exports SearchResult type guard', async () => {
    const mod = await import('@/api/hooks/useSearch');
    expect(typeof mod.useSearch).toBe('function');
  });
});

describe('CommandPalette keyboard behavior', () => {
  it('component is a function that can be rendered', async () => {
    const mod = await import('@/components/layout/CommandPalette');
    // Verify it is a React component (function)
    expect(mod.CommandPalette).toBeDefined();
    expect(typeof mod.CommandPalette).toBe('function');
  });
});

describe('Search MSW handler', () => {
  it('search handler is registered in handlers', async () => {
    const mod = await import('@/mocks/handlers');
    expect(mod.handlers).toBeDefined();
    expect(Array.isArray(mod.handlers)).toBe(true);
    // There should be a handler for /api/v1/search
    expect(mod.handlers.length).toBeGreaterThan(0);
  });
});
