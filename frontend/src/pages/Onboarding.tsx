import { useEffect } from 'react';
import { useNavigate } from '@tanstack/react-router';
import {
  OnboardingWizard,
  isOnboardingComplete,
} from '@/components/onboarding/OnboardingWizard.tsx';
import { useAuth } from '@/lib/auth.tsx';

/**
 * Onboarding page shown on first login for Org Admin / Security Manager roles.
 * Redirects to dashboard if onboarding was already completed or if user lacks required role.
 */
export function Onboarding(): React.ReactElement {
  const navigate = useNavigate();
  const { user } = useAuth();

  const shouldShow = user?.role === 'org-admin' || user?.role === 'security-manager';

  useEffect(() => {
    if (isOnboardingComplete() || !shouldShow) {
      void navigate({ to: '/' });
    }
  }, [navigate, shouldShow]);

  // Redirect non-OA/SM roles to dashboard
  if (!shouldShow) {
    return (
      <div className="card" style={{ maxWidth: '500px', margin: '60px auto', textAlign: 'center' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-1)' }}>
          Getting Started
        </h2>
        <p style={{ fontSize: '12px', color: 'var(--text-3)', marginBottom: '16px' }}>
          Onboarding is managed by your Organization Admin or Security Manager.
          Check the dashboard for your current projects and findings.
        </p>
        <button className="btn btn-accent" onClick={() => void navigate({ to: '/' })}>
          Go to Dashboard
        </button>
      </div>
    );
  }

  const handleComplete = (): void => {
    void navigate({ to: '/' });
  };

  return (
    <div style={{ maxWidth: '700px', margin: '40px auto', padding: '0 20px' }}>
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h1
          style={{
            fontSize: '22px',
            fontWeight: 700,
            color: 'var(--accent)',
            marginBottom: '4px',
          }}
        >
          Welcome to CipherRadar
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-3)' }}>
          {user?.name ? `Hello ${user.name}, let's` : "Let's"} get your workspace set up in a few steps.
        </p>
      </div>

      <OnboardingWizard onComplete={handleComplete} />
    </div>
  );
}
