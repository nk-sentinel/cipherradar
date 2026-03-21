import { useState } from 'react';
import type { Finding } from '@/mocks/data/findings';
import { SeverityBadge } from './SeverityBadge';
import { QuantumBadge } from './QuantumBadge';
import { FindingRemediation } from '@/pages/repo/FindingRemediation.tsx';

interface FindingDetailProps {
  finding: Finding;
  onClose: () => void;
}

function borderColorForSeverity(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical':
      return 'var(--red)';
    case 'high':
      return 'var(--orange)';
    case 'medium':
      return 'var(--yellow)';
    default:
      return 'var(--border)';
  }
}

export function FindingDetail({ finding, onClose }: FindingDetailProps): React.ReactElement {
  const { code } = finding;
  const [showRemediation, setShowRemediation] = useState(false);

  return (
    <div
      className="card"
      data-testid="finding-detail"
      style={{ borderColor: borderColorForSeverity(finding.severity) }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '12px',
        }}
      >
        <div>
          <SeverityBadge severity={finding.severity} long />
          <strong style={{ marginLeft: '8px' }}>{finding.title}</strong>
          <div
            style={{
              fontSize: '10px',
              color: 'var(--text-3)',
              marginTop: '4px',
            }}
          >
            {finding.file}:{finding.line} &middot; Pass {finding.pass} &middot; Rule:{' '}
            {finding.ruleId}
          </div>
        </div>
        <button className="btn btn-outline" onClick={onClose}>
          Close
        </button>
      </div>

      {/* 4-column grid */}
      <div
        className="g4"
        style={{ marginBottom: '12px' }}
      >
        <div>
          <div className="field-label">Quantum</div>
          <QuantumBadge status={finding.quantumStatus} long />
        </div>
        <div>
          <div className="field-label">Confidence</div>
          <span style={{ fontSize: '12px' }}>
            {finding.confidence.charAt(0).toUpperCase() + finding.confidence.slice(1)}
          </span>
        </div>
        <div>
          <div className="field-label">Asset Type</div>
          <span style={{ fontSize: '12px' }}>{finding.assetType}</span>
        </div>
        <div>
          <div className="field-label">Algorithm</div>
          <span style={{ fontSize: '12px' }}>{finding.algorithm ?? 'N/A'}</span>
        </div>
      </div>

      {/* Source code */}
      <div className="field-label">Source Code</div>
      <div className="code">
        {code.lines.map((line, idx) => {
          const lineNum = code.startLine + idx;
          const isHighlighted = code.highlightLines.includes(lineNum);
          return (
            <div
              key={lineNum}
              className={`code-line${isHighlighted ? ' code-hl' : ''}`}
            >
              <span className="code-num">{lineNum}</span>
              {' '}{line}
            </div>
          );
        })}
      </div>

      {/* Remediation */}
      <div className="alert alert-warn" style={{ marginTop: '12px' }}>
        <strong>Remediation:</strong>&nbsp;{finding.remediation}
      </div>

      {/* Get Fix button */}
      <div style={{ marginTop: '12px' }}>
        <button
          className="btn btn-accent"
          onClick={() => setShowRemediation((prev) => !prev)}
        >
          {showRemediation ? 'Hide Fix' : 'Get Fix'}
        </button>
      </div>

      {/* Remediation diff panel */}
      {showRemediation && (
        <FindingRemediation findingId={finding.id} />
      )}
    </div>
  );
}
