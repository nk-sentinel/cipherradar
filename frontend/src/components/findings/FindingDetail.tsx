import { useState } from 'react';
import type { Finding } from '@/mocks/data/findings';
import { SeverityBadge } from './SeverityBadge';
import { QuantumBadge } from './QuantumBadge';
import { FindingStatusBadge } from './FindingStatusBadge';
import { DetectionBadge } from './DetectionBadge';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { FindingRemediation } from '@/pages/repo/FindingRemediation.tsx';

const EXT_TO_LANG: Record<string, string> = {
  '.java': 'java',
  '.py': 'python',
  '.js': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'tsx',
  '.jsx': 'jsx',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.c': 'c',
  '.cpp': 'cpp',
  '.cs': 'csharp',
  '.php': 'php',
  '.swift': 'swift',
  '.kt': 'kotlin',
  '.env': 'ini',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.json': 'json',
  '.xml': 'xml',
  '.conf': 'ini',
  '.cnf': 'ini',
};

function detectLanguage(filename: string): string {
  const ext = filename.slice(filename.lastIndexOf('.'));
  return EXT_TO_LANG[ext] ?? 'text';
}

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

      {/* Info grid */}
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

      <div
        className="g4"
        style={{ marginBottom: '12px' }}
      >
        <div>
          <div className="field-label">Status</div>
          <FindingStatusBadge status={finding.status} />
        </div>
        <div>
          <div className="field-label">Detection</div>
          <DetectionBadge pass={finding.pass} />
        </div>
        <div>
          <div className="field-label">Assignee</div>
          <span style={{ fontSize: '12px' }}>{finding.assignee ?? 'Unassigned'}</span>
        </div>
        <div>
          <div className="field-label">First Seen</div>
          <span style={{ fontSize: '12px' }}>
            {new Date(finding.firstSeen).toLocaleDateString()}
          </span>
        </div>
      </div>

      {/* Source code — with syntax highlighting */}
      <div className="field-label">Source Code</div>
      <CodeBlock
        code={code.lines.join('\n')}
        language={detectLanguage(finding.file)}
      />

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
