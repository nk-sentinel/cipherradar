import { useToast } from '@/lib/use-toast.ts';
import type { Remediation, RemediationConfidence, RemediationProvider } from '@/mocks/data/remediation.ts';
import { cn } from '@/lib/utils.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function confidenceBadgeClass(confidence: RemediationConfidence): string {
  switch (confidence) {
    case 'high':
      return 'b-safe';
    case 'medium':
      return 'b-med';
    case 'low':
      return 'b-high';
  }
}

function providerLabel(provider: RemediationProvider): string {
  switch (provider) {
    case 'anthropic':
      return 'Anthropic';
    case 'openai':
      return 'OpenAI';
    case 'ollama':
      return 'Ollama';
  }
}

// ---------------------------------------------------------------------------
// Side-by-side diff view
// ---------------------------------------------------------------------------

function DiffView({
  originalCode,
  fixedCode,
}: {
  originalCode: string;
  fixedCode: string;
}): React.ReactElement {
  const originalLines = originalCode.split('\n');
  const fixedLines = fixedCode.split('\n');

  return (
    <div
      data-testid="remediation-diff"
      style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}
    >
      {/* Original (left, red) */}
      <div>
        <div
          style={{
            fontSize: '10px',
            fontWeight: 600,
            color: 'var(--red)',
            marginBottom: '4px',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          Original
        </div>
        <div
          className="code"
          style={{ borderColor: 'var(--red)', borderWidth: '1px', borderStyle: 'solid' }}
        >
          {originalLines.map((line, idx) => (
            <div
              key={idx}
              className="code-line"
              style={{ background: 'rgba(239, 68, 68, 0.08)' }}
            >
              <span className="code-num">{idx + 1}</span>
              <span style={{ color: 'var(--red)' }}>- </span>
              {line}
            </div>
          ))}
        </div>
      </div>

      {/* Fixed (right, green) */}
      <div>
        <div
          style={{
            fontSize: '10px',
            fontWeight: 600,
            color: 'var(--green)',
            marginBottom: '4px',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          Fixed
        </div>
        <div
          className="code"
          style={{ borderColor: 'var(--green)', borderWidth: '1px', borderStyle: 'solid' }}
        >
          {fixedLines.map((line, idx) => (
            <div
              key={idx}
              className="code-line"
              style={{ background: 'rgba(34, 197, 94, 0.08)' }}
            >
              <span className="code-num">{idx + 1}</span>
              <span style={{ color: 'var(--green)' }}>+ </span>
              {line}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export interface RemediationResultProps {
  remediation: Remediation;
  onRegenerate: () => void;
  isRegenerating: boolean;
}

/**
 * Displays the AI-generated remediation result with side-by-side diff,
 * explanation, confidence score, provider name, and copy button.
 */
export function RemediationResult({
  remediation,
  onRegenerate,
  isRegenerating,
}: RemediationResultProps): React.ReactElement {
  const { toast } = useToast();

  const handleCopyFix = async () => {
    try {
      await navigator.clipboard.writeText(remediation.diff.fixedCode);
      toast({ title: 'Fix copied to clipboard', variant: 'success' });
    } catch {
      toast({ title: 'Failed to copy to clipboard', variant: 'error' });
    }
  };

  return (
    <div data-testid="remediation-result">
      {/* Badges row */}
      <div
        style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}
      >
        <span className={cn('badge', confidenceBadgeClass(remediation.confidence))}>
          {remediation.confidence.charAt(0).toUpperCase() + remediation.confidence.slice(1)}{' '}
          Confidence
        </span>
        <span
          className="badge"
          style={{ background: 'var(--bg-3)', color: 'var(--text-2)' }}
        >
          {providerLabel(remediation.provider)}
        </span>
      </div>

      {/* Side-by-side diff */}
      <DiffView
        originalCode={remediation.diff.originalCode}
        fixedCode={remediation.diff.fixedCode}
      />

      {/* Explanation */}
      <div className="alert alert-warn" style={{ marginTop: '12px' }}>
        <strong>Explanation:</strong>&nbsp;{remediation.explanation}
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
        <button
          className="btn btn-accent"
          onClick={() => void handleCopyFix()}
          data-testid="copy-fix-btn"
        >
          Copy Fix
        </button>
        <button
          className="btn btn-outline"
          disabled={isRegenerating}
          onClick={onRegenerate}
        >
          {isRegenerating ? 'Regenerating...' : 'Regenerate'}
        </button>
      </div>
    </div>
  );
}
