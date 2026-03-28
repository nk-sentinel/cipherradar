import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/api/client';
import { useAuth } from '@/lib/auth';
import type { Finding, FindingStatus } from '@/mocks/data/findings';
import { SeverityBadge } from './SeverityBadge';
import { QuantumBadge } from './QuantumBadge';
import { FindingStatusBadge, formatStatus } from './FindingStatusBadge';
import { DetectionBadge } from './DetectionBadge';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { FindingRemediation } from '@/pages/repo/FindingRemediation.tsx';
import type { Role } from '@/lib/roles';

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

// ---------------------------------------------------------------------------
// RBAC for status changes (D14/D17)
// ---------------------------------------------------------------------------

const STATUS_CHANGE_ROLES: Role[] = ['org-admin', 'security-manager', 'security-engineer'];
const FP_REQUEST_ROLES: Role[] = ['org-admin', 'security-manager', 'security-engineer', 'team-manager', 'developer'];
const RA_REQUEST_ROLES: Role[] = ['org-admin', 'security-manager', 'security-engineer', 'team-manager', 'developer'];
const DIRECT_FP_RA_ROLES: Role[] = ['org-admin', 'security-manager'];

const ALLOWED_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  open: ['in_review', 'in_progress', 'resolved', 'risk_accepted', 'false_positive'],
  in_review: ['open', 'in_progress', 'resolved', 'risk_accepted', 'false_positive'],
  in_progress: ['open', 'in_review', 'resolved', 'risk_accepted', 'false_positive'],
  resolved: ['open'],
  risk_accepted: ['open'],
  false_positive: ['open'],
};

const REASON_CATEGORIES = [
  'Acceptable risk level',
  'Compensating controls in place',
  'Short-lived key/token',
  'Internal-only service',
  'Migration planned',
  'Other',
];

// ---------------------------------------------------------------------------
// Justification Modal
// ---------------------------------------------------------------------------

function JustificationModal({
  type,
  onSubmit,
  onClose,
}: {
  type: 'risk_accepted' | 'false_positive';
  onSubmit: (data: { justification: string; reasonCategory?: string; reviewDate?: string }) => void;
  onClose: () => void;
}): React.ReactElement {
  const [justification, setJustification] = useState('');
  const [reasonCategory, setReasonCategory] = useState(REASON_CATEGORIES[0]);
  const [reviewDate, setReviewDate] = useState('');
  const isRA = type === 'risk_accepted';

  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal card" style={{ maxWidth: '440px', width: '100%' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '12px' }}>
          Justification Required
        </h3>
        {isRA && (
          <div style={{ marginBottom: '8px' }}>
            <label className="field-label">Reason Category</label>
            <select
              className="input"
              value={reasonCategory}
              onChange={(e) => setReasonCategory(e.target.value)}
            >
              {REASON_CATEGORIES.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
        )}
        <div style={{ marginBottom: '8px' }}>
          <label className="field-label">Justification</label>
          <textarea
            className="input"
            style={{ minHeight: '60px', resize: 'vertical', width: '100%' }}
            required
            placeholder="Explain why..."
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
          />
        </div>
        {isRA && (
          <div style={{ marginBottom: '8px' }}>
            <label className="field-label">Review Date</label>
            <input
              className="input"
              type="date"
              required
              value={reviewDate}
              onChange={(e) => setReviewDate(e.target.value)}
            />
          </div>
        )}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-accent"
            disabled={!justification.trim() || (isRA && !reviewDate)}
            onClick={() => onSubmit({
              justification: justification.trim(),
              reasonCategory: isRA ? reasonCategory : undefined,
              reviewDate: isRA ? reviewDate : undefined,
            })}
          >
            Submit
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FP/RA Request Modal
// ---------------------------------------------------------------------------

function RequestModal({
  type,
  findingId,
  onClose,
}: {
  type: 'fp' | 'ra';
  findingId: string;
  onClose: () => void;
}): React.ReactElement {
  const [justification, setJustification] = useState('');
  const [reasonCategory, setReasonCategory] = useState(REASON_CATEGORIES[0]);
  const [reviewDate, setReviewDate] = useState('');
  const queryClient = useQueryClient();
  const isRA = type === 'ra';

  const submitRequest = useMutation({
    mutationFn: async (payload: Record<string, unknown>) =>
      apiClient(`/findings/${findingId}/requests`, { method: 'POST', body: payload }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      onClose();
    },
    onError: (err: Error) => {
      console.error('[CipherRadar] Failed to submit request:', err.message);
    },
  });

  return (
    <div className="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal card" style={{ maxWidth: '440px', width: '100%' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '12px' }}>
          Request {type === 'fp' ? 'False Positive' : 'Risk Acceptance'} Review
        </h3>
        {isRA && (
          <div style={{ marginBottom: '8px' }}>
            <label className="field-label">Reason Category</label>
            <select
              className="input"
              value={reasonCategory}
              onChange={(e) => setReasonCategory(e.target.value)}
            >
              {REASON_CATEGORIES.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
        )}
        <div style={{ marginBottom: '8px' }}>
          <label className="field-label">Justification</label>
          <textarea
            className="input"
            style={{ minHeight: '60px', resize: 'vertical', width: '100%' }}
            required
            placeholder="Explain why this should be reviewed..."
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
          />
        </div>
        {isRA && (
          <div style={{ marginBottom: '8px' }}>
            <label className="field-label">Suggested Review Date</label>
            <input
              className="input"
              type="date"
              required
              value={reviewDate}
              onChange={(e) => setReviewDate(e.target.value)}
            />
          </div>
        )}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-accent"
            disabled={!justification.trim() || (isRA && !reviewDate) || submitRequest.isPending}
            onClick={() => submitRequest.mutate({
              type: type === 'fp' ? 'false_positive' : 'risk_acceptance',
              justification: justification.trim(),
              reasonCategory: isRA ? reasonCategory : undefined,
              reviewDate: isRA ? reviewDate : undefined,
            })}
          >
            {submitRequest.isPending ? 'Submitting...' : 'Submit Request'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HistoryEntry {
  id: string;
  fromStatus: string;
  toStatus: string;
  changedBy: string;
  changedAt: string;
  justification?: string;
}

interface Comment {
  id: string;
  author: string;
  text: string;
  createdAt: string;
}

interface FindingDetailProps {
  finding: Finding & { reopenCount?: number };
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
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [showRemediation, setShowRemediation] = useState(false);
  const [requestModalOpen, setRequestModalOpen] = useState<'fp' | 'ra' | null>(null);
  const [justificationModalOpen, setJustificationModalOpen] = useState<'risk_accepted' | 'false_positive' | null>(null);
  const [newComment, setNewComment] = useState('');

  const role = (user?.role ?? 'guest') as Role;
  const canChangeStatus = STATUS_CHANGE_ROLES.includes(role);
  const canDirectFPRA = DIRECT_FP_RA_ROLES.includes(role);
  const canRequestFP = FP_REQUEST_ROLES.includes(role) && !canDirectFPRA;
  const canRequestRA = RA_REQUEST_ROLES.includes(role) && !canDirectFPRA;

  const allowedTransitions = ALLOWED_TRANSITIONS[finding.status] ?? [];

  // Status change mutation
  const statusMutation = useMutation({
    mutationFn: async (payload: { status: FindingStatus; justification?: string; reasonCategory?: string; reviewDate?: string }) =>
      apiClient(`/findings/${finding.id}/status`, { method: 'PATCH', body: payload }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      void queryClient.invalidateQueries({ queryKey: ['finding-history', finding.id] });
    },
    onError: (err: Error) => {
      console.error('[CipherRadar] Failed to change finding status:', err.message);
    },
  });

  // Status history
  const { data: history } = useQuery<HistoryEntry[]>({
    queryKey: ['finding-history', finding.id],
    queryFn: () => apiClient(`/findings/${finding.id}/history`),
  });

  // Comments
  const { data: comments } = useQuery<Comment[]>({
    queryKey: ['finding-comments', finding.id],
    queryFn: () => apiClient(`/findings/${finding.id}/comments`),
  });

  const addCommentMutation = useMutation({
    mutationFn: async (text: string) =>
      apiClient(`/findings/${finding.id}/comments`, { method: 'POST', body: { text } }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['finding-comments', finding.id] });
      setNewComment('');
    },
    onError: (err: Error) => {
      console.error('[CipherRadar] Failed to add comment:', err.message);
    },
  });

  const handleStatusChange = (newStatus: string) => {
    const status = newStatus as FindingStatus;
    if (status === 'risk_accepted' || status === 'false_positive') {
      setJustificationModalOpen(status);
    } else {
      statusMutation.mutate({ status });
    }
  };

  const handleJustificationSubmit = (data: { justification: string; reasonCategory?: string; reviewDate?: string }) => {
    if (!justificationModalOpen) return;
    statusMutation.mutate({
      status: justificationModalOpen,
      justification: data.justification,
      reasonCategory: data.reasonCategory,
      reviewDate: data.reviewDate,
    });
    setJustificationModalOpen(null);
  };

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
          {/* H4: Reopened badge */}
          {(finding.reopenCount ?? 0) > 0 && (
            <span
              className="badge"
              style={{
                marginLeft: '8px',
                background: 'color-mix(in srgb, var(--orange) 15%, transparent)',
                color: 'var(--orange)',
                border: '1px solid color-mix(in srgb, var(--orange) 30%, transparent)',
              }}
            >
              Reopened
            </span>
          )}
          <div
            style={{
              fontSize: '10px',
              color: 'var(--text-3)',
              marginTop: '4px',
            }}
          >
            {/* H7: Detection label instead of "Pass N" */}
            {finding.file}:{finding.line} &middot;{' '}
            {finding.pass === 1 ? 'Pattern' : finding.pass === 2 ? 'Taint' : `Pass ${String(finding.pass)}`}
            {' '}&middot; Rule: {finding.ruleId}
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <FindingStatusBadge status={finding.status} />
            {/* C6: Status change dropdown */}
            {canChangeStatus && allowedTransitions.length > 0 && (
              <select
                className="input"
                value={finding.status}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={statusMutation.isPending}
                data-testid="status-change-select"
                style={{ fontSize: '10px', padding: '2px 6px', width: 'auto', minWidth: '100px' }}
              >
                <option value={finding.status}>{formatStatus(finding.status)}</option>
                {allowedTransitions.map((s) => (
                  <option key={s} value={s}>{formatStatus(s)}</option>
                ))}
              </select>
            )}
          </div>
          {/* C7: FP/RA request buttons */}
          <div style={{ display: 'flex', gap: '4px', marginTop: '6px', flexWrap: 'wrap' }}>
            {canRequestFP && (
              <button
                className="btn btn-outline"
                style={{ fontSize: '10px', padding: '2px 8px' }}
                onClick={() => setRequestModalOpen('fp')}
                data-testid="request-fp-btn"
              >
                Request FP Review
              </button>
            )}
            {canRequestRA && (
              <button
                className="btn btn-outline"
                style={{ fontSize: '10px', padding: '2px 8px' }}
                onClick={() => setRequestModalOpen('ra')}
                data-testid="request-ra-btn"
              >
                Request Risk Acceptance
              </button>
            )}
          </div>
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

      {/* H2: Status history section */}
      <div style={{ marginTop: '16px' }}>
        <div className="field-label">Status History</div>
        {history && history.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
            {history.slice(0, 5).map((h) => (
              <div
                key={h.id}
                style={{
                  fontSize: '11px',
                  color: 'var(--text-2)',
                  display: 'flex',
                  gap: '6px',
                  alignItems: 'center',
                }}
                data-testid={`history-entry-${h.id}`}
              >
                <span style={{ color: 'var(--text-4)' }}>{new Date(h.changedAt).toLocaleDateString()}</span>
                <span>{h.changedBy}</span>
                <span style={{ color: 'var(--text-3)' }}>{h.fromStatus} &rarr; {h.toStatus}</span>
                {h.justification && (
                  <span style={{ color: 'var(--text-4)', fontStyle: 'italic' }}>&mdash; {h.justification}</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>No status changes recorded.</p>
        )}
      </div>

      {/* H3: Comments section */}
      <div style={{ marginTop: '16px' }}>
        <div className="field-label">Comments</div>
        {comments && comments.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
            {comments.map((c) => (
              <div
                key={c.id}
                style={{
                  fontSize: '12px',
                  padding: '8px',
                  background: 'var(--bg-2)',
                  borderRadius: 'var(--radius)',
                  border: '1px solid var(--border)',
                }}
                data-testid={`comment-${c.id}`}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <strong style={{ fontSize: '11px' }}>{c.author}</strong>
                  <span style={{ fontSize: '10px', color: 'var(--text-4)' }}>
                    {new Date(c.createdAt).toLocaleDateString()}
                  </span>
                </div>
                <div style={{ color: 'var(--text-2)' }}>{c.text}</div>
              </div>
            ))}
          </div>
        ) : (
          <p style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>No comments yet.</p>
        )}
        <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
          <textarea
            className="input"
            style={{ flex: 1, minHeight: '40px', resize: 'vertical', fontSize: '12px' }}
            placeholder="Add a comment..."
            value={newComment}
            onChange={(e) => setNewComment(e.target.value)}
            data-testid="comment-input"
          />
          <button
            className="btn btn-outline"
            style={{ alignSelf: 'flex-end', fontSize: '11px', padding: '4px 10px' }}
            disabled={!newComment.trim() || addCommentMutation.isPending}
            onClick={() => addCommentMutation.mutate(newComment.trim())}
            data-testid="comment-submit"
          >
            {addCommentMutation.isPending ? 'Posting...' : 'Post'}
          </button>
        </div>
      </div>

      {/* FP/RA request modal (C7) */}
      {requestModalOpen && (
        <RequestModal
          type={requestModalOpen}
          findingId={finding.id}
          onClose={() => setRequestModalOpen(null)}
        />
      )}

      {/* Justification modal for direct FP/RA status changes */}
      {justificationModalOpen && (
        <JustificationModal
          type={justificationModalOpen}
          onSubmit={handleJustificationSubmit}
          onClose={() => setJustificationModalOpen(null)}
        />
      )}
    </div>
  );
}
