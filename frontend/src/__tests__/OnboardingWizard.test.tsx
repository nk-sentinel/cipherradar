import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('OnboardingWizard component', () => {
  it('exports the OnboardingWizard component', async () => {
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(typeof mod.OnboardingWizard).toBe('function');
  });

  it('exports ONBOARDING_STORAGE_KEY constant', async () => {
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(mod.ONBOARDING_STORAGE_KEY).toBe('onboarding_complete');
  });

  it('exports isOnboardingComplete helper', async () => {
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(typeof mod.isOnboardingComplete).toBe('function');
  });

  it('exports markOnboardingComplete helper', async () => {
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(typeof mod.markOnboardingComplete).toBe('function');
  });
});

describe('isOnboardingComplete', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns false when localStorage is empty', async () => {
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(mod.isOnboardingComplete()).toBe(false);
  });

  it('returns true when localStorage has onboarding_complete set', async () => {
    localStorage.setItem('onboarding_complete', 'true');
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(mod.isOnboardingComplete()).toBe(true);
  });

  it('returns false when value is not "true"', async () => {
    localStorage.setItem('onboarding_complete', 'false');
    const mod = await import('@/components/onboarding/OnboardingWizard');
    expect(mod.isOnboardingComplete()).toBe(false);
  });
});

describe('markOnboardingComplete', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('sets localStorage onboarding_complete to true', async () => {
    const mod = await import('@/components/onboarding/OnboardingWizard');
    mod.markOnboardingComplete();
    expect(localStorage.getItem('onboarding_complete')).toBe('true');
  });
});

describe('Onboarding page', () => {
  it('exports the Onboarding page component', async () => {
    const mod = await import('@/pages/Onboarding');
    expect(typeof mod.Onboarding).toBe('function');
  });
});
