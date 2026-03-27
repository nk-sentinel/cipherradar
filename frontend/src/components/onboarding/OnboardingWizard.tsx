import { useState, useCallback } from 'react';

export interface OnboardingWizardProps {
  onComplete: () => void;
}

export type OnboardingStep = 'connect' | 'import' | 'scan';

const STEPS: { key: OnboardingStep; label: string; number: number }[] = [
  { key: 'connect', label: 'Connect a Git Provider', number: 1 },
  { key: 'import', label: 'Import Projects', number: 2 },
  { key: 'scan', label: 'Run Your First Scan', number: 3 },
];

export const ONBOARDING_STORAGE_KEY = 'onboarding_complete';

export function isOnboardingComplete(): boolean {
  try {
    return localStorage.getItem(ONBOARDING_STORAGE_KEY) === 'true';
  } catch {
    return false;
  }
}

export function markOnboardingComplete(): void {
  try {
    localStorage.setItem(ONBOARDING_STORAGE_KEY, 'true');
  } catch {
    /* test/SSR env */
  }
}

export function OnboardingWizard({ onComplete }: OnboardingWizardProps): React.ReactElement {
  const [currentStep, setCurrentStep] = useState<OnboardingStep>('connect');

  const currentIndex = STEPS.findIndex((s) => s.key === currentStep);

  const handleNext = useCallback(() => {
    if (currentIndex < STEPS.length - 1) {
      setCurrentStep(STEPS[currentIndex + 1]!.key);
    } else {
      markOnboardingComplete();
      onComplete();
    }
  }, [currentIndex, onComplete]);

  const handleSkip = useCallback(() => {
    markOnboardingComplete();
    onComplete();
  }, [onComplete]);

  return (
    <div data-testid="onboarding-wizard">
      {/* Step indicators */}
      <div
        data-testid="step-indicators"
        style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '24px',
          marginBottom: '32px',
        }}
      >
        {STEPS.map((step, idx) => (
          <div
            key={step.key}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <div
              data-testid={`step-indicator-${step.key}`}
              style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '12px',
                fontWeight: 700,
                background: idx <= currentIndex ? 'var(--accent)' : 'var(--bg-3)',
                color: idx <= currentIndex ? 'var(--bg-0)' : 'var(--text-4)',
                border: idx === currentIndex ? '2px solid var(--accent-hover)' : '2px solid transparent',
              }}
            >
              {idx < currentIndex ? '\u2713' : step.number}
            </div>
            <span
              style={{
                fontSize: '12px',
                color: idx === currentIndex ? 'var(--text-1)' : 'var(--text-3)',
                fontWeight: idx === currentIndex ? 600 : 400,
              }}
            >
              {step.label}
            </span>
            {idx < STEPS.length - 1 && (
              <div
                style={{
                  width: '40px',
                  height: '2px',
                  background: idx < currentIndex ? 'var(--accent)' : 'var(--border)',
                  marginLeft: '8px',
                }}
              />
            )}
          </div>
        ))}
      </div>

      {/* Step content */}
      <div className="card" style={{ textAlign: 'center', padding: '32px' }}>
        {currentStep === 'connect' && (
          <div data-testid="step-connect">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-1)' }}>
              Connect a Git Provider
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-3)', marginBottom: '20px' }}>
              Link your GitHub, GitLab, or Bitbucket account to import projects for scanning.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', marginBottom: '20px' }}>
              <a
                href="/admin/integrations"
                className="btn btn-outline"
                style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                data-testid="connect-github-btn"
              >
                {'\u2B21'} GitHub
              </a>
              <a
                href="/admin/integrations"
                className="btn btn-outline"
                style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                data-testid="connect-gitlab-btn"
              >
                {'\u2B22'} GitLab
              </a>
              <a
                href="/admin/integrations"
                className="btn btn-outline"
                style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                data-testid="connect-bitbucket-btn"
              >
                {'\u2B23'} Bitbucket
              </a>
            </div>
          </div>
        )}

        {currentStep === 'import' && (
          <div data-testid="step-import">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-1)' }}>
              Import Projects
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-3)', marginBottom: '20px' }}>
              Select repositories to import and monitor for cryptographic assets.
            </p>
            <a
              href="/repos"
              className="btn btn-accent"
              style={{ textDecoration: 'none' }}
              data-testid="go-to-projects-btn"
            >
              Go to Projects
            </a>
          </div>
        )}

        {currentStep === 'scan' && (
          <div data-testid="step-scan">
            <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-1)' }}>
              Run Your First Scan
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-3)', marginBottom: '20px' }}>
              Trigger a scan on one of your imported projects to generate a CBOM.
            </p>
            <a
              href="/"
              className="btn btn-accent"
              style={{ textDecoration: 'none' }}
              data-testid="go-to-dashboard-btn"
            >
              Go to Dashboard
            </a>
          </div>
        )}
      </div>

      {/* Navigation buttons */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginTop: '20px',
        }}
      >
        <button
          className="btn btn-outline"
          onClick={handleSkip}
          data-testid="onboarding-skip-btn"
        >
          Skip
        </button>
        <button
          className="btn btn-accent"
          onClick={handleNext}
          data-testid="onboarding-next-btn"
        >
          {currentIndex < STEPS.length - 1 ? 'Next' : 'Finish'}
        </button>
      </div>
    </div>
  );
}
