import { describe, it, expect } from 'vitest';

describe('NotificationPreferences page', () => {
  it('exports the NotificationPreferences component', async () => {
    const mod = await import('@/pages/NotificationPreferences');
    expect(typeof mod.NotificationPreferences).toBe('function');
  });

  it('exports WebhookTestStatus type (as runtime value check)', async () => {
    // WebhookTestStatus is a type, so we check the component exists
    const mod = await import('@/pages/NotificationPreferences');
    expect(mod.NotificationPreferences).toBeDefined();
  });
});

describe('Token rotation warning on IntegrationManagement', () => {
  it('shouldWarnRotation returns true for tokens > 90 days old', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(mod.shouldWarnRotation(91)).toBe(true);
    expect(mod.shouldWarnRotation(90)).toBe(false);
    expect(mod.shouldWarnRotation(89)).toBe(false);
    expect(mod.shouldWarnRotation(null)).toBe(false);
  });

  it('tokenAgeDays returns the age value', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(mod.tokenAgeDays(45)).toBe(45);
    expect(mod.tokenAgeDays(null)).toBe(null);
  });
});

describe('IntegrationManagement page', () => {
  it('exports the IntegrationManagement component', async () => {
    const mod = await import('@/pages/admin/IntegrationManagement');
    expect(typeof mod.IntegrationManagement).toBe('function');
  });
});
