import { describe, it, expect } from 'vitest';

describe('useAuditLog hooks', () => {
  it('exports useAuditLogPaginated hook', async () => {
    const mod = await import('@/api/hooks/useAuditLog');
    expect(typeof mod.useAuditLogPaginated).toBe('function');
  });

  it('exports useExportAuditLog hook', async () => {
    const mod = await import('@/api/hooks/useAuditLog');
    expect(typeof mod.useExportAuditLog).toBe('function');
  });

  it('exports DATE_PRESETS', async () => {
    const mod = await import('@/api/hooks/useAuditLog');
    expect(mod.DATE_PRESETS).toBeDefined();
    expect(mod.DATE_PRESETS.length).toBe(5);
    const values = mod.DATE_PRESETS.map((p: { value: string }) => p.value);
    expect(values).toContain('today');
    expect(values).toContain('7d');
    expect(values).toContain('30d');
    expect(values).toContain('90d');
    expect(values).toContain('custom');
  });

  it('presetToDateRange returns correct range for 7d', async () => {
    const mod = await import('@/api/hooks/useAuditLog');
    const range = mod.presetToDateRange('7d');
    expect(range).not.toBeNull();
    const from = new Date(range!.from);
    const to = new Date(range!.to);
    const diff = (to.getTime() - from.getTime()) / (1000 * 60 * 60 * 24);
    expect(diff).toBeGreaterThanOrEqual(6.9);
    expect(diff).toBeLessThanOrEqual(7.1);
  });

  it('presetToDateRange returns null for custom', async () => {
    const mod = await import('@/api/hooks/useAuditLog');
    const range = mod.presetToDateRange('custom');
    expect(range).toBeNull();
  });
});

describe('AuditLog page', () => {
  it('exports the AuditLog component', async () => {
    const mod = await import('@/pages/admin/AuditLog');
    expect(typeof mod.AuditLog).toBe('function');
  });
});

describe('Audit log mock data', () => {
  it('getAuditLog returns entries with expected fields', async () => {
    const mod = await import('@/mocks/data/admin');
    const entries = mod.getAuditLog();
    expect(entries.length).toBeGreaterThan(0);
    const first = entries[0];
    expect(first).toHaveProperty('id');
    expect(first).toHaveProperty('timestamp');
    expect(first).toHaveProperty('user');
    expect(first).toHaveProperty('action');
    expect(first).toHaveProperty('resource');
  });
});
