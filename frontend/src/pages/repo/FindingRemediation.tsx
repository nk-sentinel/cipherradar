import { useState } from 'react';
import { useRemediation, useRequestRemediation } from '@/api/hooks/useRemediation.ts';
import { ConsentModal } from '@/components/findings/ConsentModal.tsx';
import { RemediationResult } from '@/components/findings/RemediationResult.tsx';

interface FindingRemediationProps {
  findingId: string;
  /** Code snippet from the finding for consent display. Falls back to placeholder. */
  codeSnippet?: string;
}

/**
 * FindingRemediation — AI remediation flow with consent modal.
 *
 * Flow:
 * 1. If cached remediation exists, show it immediately (no consent needed).
 * 2. If no remediation, show "Get Fix" button.
 * 3. Clicking "Get Fix" opens consent modal showing exact code to be sent.
 * 4. After consent: loading state -> result with side-by-side diff.
 * 5. "Copy Fix" button copies the fixed code to clipboard.
 * 6. "Regenerate" re-triggers the flow (skips consent if already given).
 */
export function FindingRemediation({
  findingId,
  codeSnippet,
}: FindingRemediationProps): React.ReactElement {
  const { data: remediation, isLoading, error } = useRemediation(findingId);
  const requestRemediation = useRequestRemediation();
  const [showConsent, setShowConsent] = useState(false);
  const [hasConsented, setHasConsented] = useState(false);

  const defaultSnippet = codeSnippet || '// Code snippet will be sent for analysis';
  const providerName = remediation?.provider
    ? remediation.provider.charAt(0).toUpperCase() + remediation.provider.slice(1)
    : 'AI Provider';

  const handleGetFix = () => {
    // If already consented (e.g., regenerate), skip modal
    if (hasConsented) {
      requestRemediation.mutate({ findingId });
      return;
    }
    setShowConsent(true);
  };

  const handleConsent = () => {
    setHasConsented(true);
    setShowConsent(false);
    requestRemediation.mutate({ findingId });
  };

  const handleRegenerate = () => {
    // Already consented, just regenerate
    requestRemediation.mutate({ findingId });
  };

  if (isLoading) {
    return (
      <div className="card" style={{ marginTop: '12px' }}>
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading remediation...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card" style={{ marginTop: '12px' }}>
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>Failed to load remediation.</p>
      </div>
    );
  }

  // No cached remediation yet — show "Get Fix" button
  if (!remediation) {
    return (
      <div className="card" style={{ marginTop: '12px' }}>
        <div style={{ textAlign: 'center', padding: '20px' }}>
          <p style={{ color: 'var(--text-2)', fontSize: '13px', marginBottom: '12px' }}>
            No remediation available for this finding yet.
          </p>
          <button
            className="btn btn-accent"
            disabled={requestRemediation.isPending}
            onClick={handleGetFix}
            data-testid="get-fix-btn"
          >
            {requestRemediation.isPending ? 'Generating...' : 'Get Fix'}
          </button>
          {requestRemediation.isError && (
            <p style={{ color: 'var(--red)', fontSize: '12px', marginTop: '8px' }}>
              Failed to generate remediation. Please try again.
            </p>
          )}
        </div>

        {/* Consent modal */}
        {showConsent && (
          <ConsentModal
            codeSnippet={defaultSnippet}
            providerName={providerName}
            onConsent={handleConsent}
            onCancel={() => setShowConsent(false)}
            isPending={requestRemediation.isPending}
          />
        )}
      </div>
    );
  }

  // Cached or freshly generated result — show it
  return (
    <div className="card" style={{ marginTop: '12px' }}>
      <div className="card-title">AI Remediation</div>
      <RemediationResult
        remediation={remediation}
        onRegenerate={handleRegenerate}
        isRegenerating={requestRemediation.isPending}
      />

      {/* Consent modal for regeneration if not yet consented */}
      {showConsent && (
        <ConsentModal
          codeSnippet={defaultSnippet}
          providerName={providerName}
          onConsent={handleConsent}
          onCancel={() => setShowConsent(false)}
          isPending={requestRemediation.isPending}
        />
      )}
    </div>
  );
}
