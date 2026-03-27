import { useEffect } from 'react';
import { useNavigate } from '@tanstack/react-router';
import {
  OnboardingWizard,
  isOnboardingComplete,
} from '@/components/onboarding/OnboardingWizard.tsx';
import { useAuth } from '@/lib/auth.tsx';

/**
 * Onboarding page shown on first login for Org Admin / Security Manager roles.
 * Redirects to dashboard if onboarding was already completed.
 */
export function Onboarding(): React.ReactElement {
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    if (isOnboardingComplete()) {
      void navigate({ to: '/' });
    }
  }, [navigate]);

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
