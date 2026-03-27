import { useState } from 'react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ConsentModalProps {
  codeSnippet: string;
  providerName: string;
  onConsent: () => void;
  onCancel: () => void;
  isPending: boolean;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Consent modal shown before sending code to the LLM for remediation.
 * Displays the exact code that will be sent, provider name, and requires
 * explicit user consent.
 */
export function ConsentModal({
  codeSnippet,
  providerName,
  onConsent,
  onCancel,
  isPending,
}: ConsentModalProps): React.ReactElement {
  const [acknowledged, setAcknowledged] = useState(false);

  return (
    <div
      data-testid="consent-modal"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        className="card"
        style={{ width: '520px', maxHeight: '80vh', overflow: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-title">Send Code for AI Remediation</div>

        <div className="alert alert-warn" style={{ marginBottom: '12px', fontSize: '12px' }}>
          The following code will be sent to <strong>{providerName}</strong> for analysis. Review
          the snippet below to ensure no sensitive data is included.
        </div>

        {/* Code preview */}
        <div
          data-testid="consent-code-preview"
          className="code"
          style={{
            maxHeight: '200px',
            overflow: 'auto',
            marginBottom: '12px',
            borderColor: 'var(--border)',
            borderWidth: '1px',
            borderStyle: 'solid',
          }}
        >
          {codeSnippet.split('\n').map((line, idx) => (
            <div key={idx} className="code-line">
              <span className="code-num">{idx + 1}</span>
              {line}
            </div>
          ))}
        </div>

        {/* Acknowledgment checkbox */}
        <label
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '8px',
            fontSize: '12px',
            color: 'var(--text-1)',
            marginBottom: '16px',
          }}
        >
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            data-testid="consent-checkbox"
            style={{ marginTop: '2px' }}
          />
          I understand this code will be sent to an external LLM provider and consent to
          proceed.
        </label>

        {/* Actions */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onCancel}>
            Cancel
          </button>
          <button
            className="btn btn-accent"
            disabled={!acknowledged || isPending}
            onClick={onConsent}
            data-testid="consent-submit"
          >
            {isPending ? 'Sending...' : 'Send for Analysis'}
          </button>
        </div>
      </div>
    </div>
  );
}
