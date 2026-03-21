import { useRemediation, useRequestRemediation } from '@/api/hooks/useRemediation.ts';
import type { Remediation, RemediationConfidence, RemediationProvider } from '@/mocks/data/remediation.ts';
import { cn } from '@/lib/utils.ts';

interface FindingRemediationProps {
  findingId: string;
}

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

function DiffView({ originalCode, fixedCode }: { originalCode: string; fixedCode: string }): React.ReactElement {
  const originalLines = originalCode.split('\n');
  const fixedLines = fixedCode.split('\n');

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
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
        <div className="code" style={{ borderColor: 'var(--red)', borderWidth: '1px', borderStyle: 'solid' }}>
          {originalLines.map((line, idx) => (
            <div
              key={idx}
              className="code-line"
              style={{ background: 'rgba(239, 68, 68, 0.08)' }}
            >
              <span className="code-num">{idx + 1}</span>
              <span style={{ color: 'var(--red)' }}>- </span>{line}
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
        <div className="code" style={{ borderColor: 'var(--green)', borderWidth: '1px', borderStyle: 'solid' }}>
          {fixedLines.map((line, idx) => (
            <div
              key={idx}
              className="code-line"
              style={{ background: 'rgba(34, 197, 94, 0.08)' }}
            >
              <span className="code-num">{idx + 1}</span>
              <span style={{ color: 'var(--green)' }}>+ </span>{line}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RemediationContent({ remediation }: { remediation: Remediation }): React.ReactElement {
  const requestRemediation = useRequestRemediation();

  return (
    <div>
      {/* Badges row */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}>
        <span className={cn('badge', confidenceBadgeClass(remediation.confidence))}>
          {remediation.confidence.charAt(0).toUpperCase() + remediation.confidence.slice(1)} Confidence
        </span>
        <span className="badge" style={{ background: 'var(--bg-3)', color: 'var(--text-2)' }}>
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
          onClick={() => {
            alert('Automatic PR creation will be available in a future release. For now, copy the suggested fix above.');
          }}
        >
          Apply Fix
        </button>
        <button
          className="btn btn-outline"
          disabled={requestRemediation.isPending}
          onClick={() => requestRemediation.mutate({ findingId: remediation.findingId })}
        >
          {requestRemediation.isPending ? 'Regenerating...' : 'Regenerate'}
        </button>
      </div>
    </div>
  );
}

export function FindingRemediation({ findingId }: FindingRemediationProps): React.ReactElement {
  const { data: remediation, isLoading, error } = useRemediation(findingId);
  const requestRemediation = useRequestRemediation();

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
            onClick={() => requestRemediation.mutate({ findingId })}
          >
            {requestRemediation.isPending ? 'Generating...' : 'Get Fix'}
          </button>
          {requestRemediation.isError && (
            <p style={{ color: 'var(--red)', fontSize: '12px', marginTop: '8px' }}>
              Failed to generate remediation. Please try again.
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ marginTop: '12px' }}>
      <div className="card-title">AI Remediation</div>
      <RemediationContent remediation={remediation} />
    </div>
  );
}
