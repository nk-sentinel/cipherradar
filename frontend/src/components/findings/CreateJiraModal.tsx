import { useState } from 'react';
import type { Finding } from '@/mocks/data/findings';
import { useCreateJiraIssue, type JiraIssueResult } from '@/api/hooks/useJira';

interface CreateJiraModalProps {
  finding: Finding;
  onClose: () => void;
}

const SEVERITY_TO_PRIORITY: Record<string, string> = {
  critical: 'Highest',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Low',
};

const JIRA_PRIORITIES = ['Highest', 'High', 'Medium', 'Low', 'Lowest'];
const JIRA_ISSUE_TYPES = ['Bug', 'Task', 'Story'];

function buildDescription(finding: Finding): string {
  const lines = [
    `**Finding:** ${finding.title}`,
    `**File:** ${finding.file}:${String(finding.line)}`,
    `**Severity:** ${finding.severity}`,
    `**Rule:** ${finding.ruleId}`,
    `**Quantum Status:** ${finding.quantumStatus}`,
    '',
    '**Code snippet:**',
    '```',
    ...finding.code.lines,
    '```',
    '',
    `**Remediation:** ${finding.remediation}`,
  ];
  return lines.join('\n');
}

export function CreateJiraModal({
  finding,
  onClose,
}: CreateJiraModalProps): React.ReactElement {
  const defaultPriority = SEVERITY_TO_PRIORITY[finding.severity] ?? 'Medium';

  const [summary, setSummary] = useState(
    `[CipherRadar] ${finding.severity.toUpperCase()}: ${finding.title}`,
  );
  const [description, setDescription] = useState(buildDescription(finding));
  const [priority, setPriority] = useState(defaultPriority);
  const [issueType, setIssueType] = useState('Bug');
  const [labels, setLabels] = useState('crypto,cipherradar');
  const [result, setResult] = useState<JiraIssueResult | null>(null);

  const createIssue = useCreateJiraIssue();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    createIssue.mutate(
      {
        findingId: finding.id,
        summary,
        description,
        priority,
        issueType,
        labels: labels
          .split(',')
          .map((l) => l.trim())
          .filter(Boolean),
      },
      {
        onSuccess: (data) => {
          setResult(data);
        },
      },
    );
  };

  return (
    <div
      className="modal-overlay"
      data-testid="jira-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal card" style={{ maxWidth: '560px', width: '100%' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '16px',
          }}
        >
          <h2 style={{ fontSize: '16px', fontWeight: 700 }}>Create Jira Issue</h2>
          <button className="btn btn-outline" onClick={onClose} type="button">
            Close
          </button>
        </div>

        {result ? (
          <div data-testid="jira-success">
            <div
              className="alert"
              style={{
                background: 'var(--green-bg, rgba(34,197,94,0.1))',
                border: '1px solid var(--green, #22c55e)',
                padding: '12px',
                borderRadius: 'var(--radius)',
                marginBottom: '12px',
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>Issue created successfully</div>
              <a
                href={result.issueUrl}
                target="_blank"
                rel="noopener noreferrer"
                data-testid="jira-success-url"
                style={{ color: 'var(--accent)', textDecoration: 'underline' }}
              >
                {result.issueKey}
              </a>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-accent" onClick={onClose}>
                Done
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            {/* Summary */}
            <div style={{ marginBottom: '12px' }}>
              <label className="field-label">Summary</label>
              <input
                type="text"
                className="input"
                style={{ width: '100%' }}
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                data-testid="jira-summary"
              />
            </div>

            {/* Description */}
            <div style={{ marginBottom: '12px' }}>
              <label className="field-label">Description</label>
              <textarea
                className="input"
                style={{ minHeight: '120px', resize: 'vertical', width: '100%' }}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                data-testid="jira-description"
              />
            </div>

            {/* Issue type + Priority row */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
              <div style={{ flex: 1 }}>
                <label className="field-label">Issue Type</label>
                <select
                  className="input"
                  style={{ width: '100%' }}
                  value={issueType}
                  onChange={(e) => setIssueType(e.target.value)}
                  data-testid="jira-issue-type"
                >
                  {JIRA_ISSUE_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label className="field-label">Priority</label>
                <select
                  className="input"
                  style={{ width: '100%' }}
                  value={priority}
                  onChange={(e) => setPriority(e.target.value)}
                  data-testid="jira-priority"
                >
                  {JIRA_PRIORITIES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Labels */}
            <div style={{ marginBottom: '12px' }}>
              <label className="field-label">Labels (comma-separated)</label>
              <input
                type="text"
                className="input"
                style={{ width: '100%' }}
                value={labels}
                onChange={(e) => setLabels(e.target.value)}
                data-testid="jira-labels"
              />
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button className="btn btn-outline" type="button" onClick={onClose}>
                Cancel
              </button>
              <button
                className="btn btn-accent"
                type="submit"
                disabled={createIssue.isPending || !summary.trim()}
                data-testid="jira-submit"
              >
                {createIssue.isPending ? 'Creating...' : 'Create Issue'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
