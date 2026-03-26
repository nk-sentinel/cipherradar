import { useState, useCallback } from 'react';
import { useRequests, useApproveRequest, useRejectRequest } from '@/api/hooks/useRequests';
import type { ReviewRequest } from '@/api/hooks/useRequests';
import { Pagination } from '@/components/ui/Pagination';
import { SeverityBadge } from '@/components/findings/SeverityBadge';
import type { Severity } from '@/mocks/data/findings';

function RejectReasonModal({
  onConfirm,
  onCancel,
}: {
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}): React.ReactElement {
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) {
      setError('A rejection reason is required.');
      return;
    }
    onConfirm(reason.trim());
  };

  return (
    <div
      className="modal-overlay"
      data-testid="reject-reason-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div className="modal card" style={{ maxWidth: '400px', width: '100%' }}>
        <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '12px' }}>
          Rejection Reason
        </h3>
        <form onSubmit={handleSubmit}>
          <textarea
            className="input"
            style={{ minHeight: '60px', resize: 'vertical', width: '100%', marginBottom: '8px' }}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Explain why this request is being rejected..."
            data-testid="reject-reason-input"
          />
          {error && (
            <div className="alert alert-warn" style={{ marginBottom: '8px' }}>
              {error}
            </div>
          )}
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button className="btn btn-outline" type="button" onClick={onCancel}>
              Cancel
            </button>
            <button className="btn btn-accent" type="submit" data-testid="reject-confirm">
              Reject
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function RequestQueue(): React.ReactElement {
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(25);
  const [rejectingId, setRejectingId] = useState<string | null>(null);

  const { data, isLoading, error } = useRequests(page, perPage);
  const approveRequest = useApproveRequest();
  const rejectRequest = useRejectRequest();

  const handleApprove = useCallback((requestId: string) => {
    approveRequest.mutate(requestId);
  }, [approveRequest]);

  const handleReject = useCallback((requestId: string, reason: string) => {
    rejectRequest.mutate({ requestId, reason });
    setRejectingId(null);
  }, [rejectRequest]);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading requests...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>Failed to load requests.</p>
      </div>
    );
  }

  const requests = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div>
      <h1
        style={{
          fontSize: '18px',
          fontWeight: 700,
          textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
          letterSpacing: '0.04em',
          marginBottom: '20px',
        }}
      >
        Pending Requests
      </h1>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>Requester</th>
              <th>Type</th>
              <th>Justification</th>
              <th>Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {requests.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-3)' }}>
                  No pending requests.
                </td>
              </tr>
            ) : (
              requests.map((req: ReviewRequest) => (
                <tr key={req.id} data-testid={`request-row-${req.id}`}>
                  <td>{req.findingSummary}</td>
                  <td>
                    <SeverityBadge severity={req.findingSeverity as Severity} />
                  </td>
                  <td>{req.requester}</td>
                  <td>
                    <span className={`badge ${req.type === 'false_positive' ? 'b-gray' : 'b-purple'}`}>
                      {req.type === 'false_positive' ? 'FP' : 'RA'}
                    </span>
                  </td>
                  <td style={{ maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {req.justification}
                  </td>
                  <td>{new Date(req.createdAt).toLocaleDateString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        className="btn btn-accent"
                        style={{ fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => handleApprove(req.id)}
                        disabled={approveRequest.isPending}
                        data-testid={`approve-${req.id}`}
                      >
                        Approve
                      </button>
                      <button
                        className="btn btn-outline"
                        style={{ fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => setRejectingId(req.id)}
                        data-testid={`reject-${req.id}`}
                      >
                        Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        <Pagination
          page={page}
          perPage={perPage}
          total={total}
          onPageChange={setPage}
          onPerPageChange={setPerPage}
        />
      </div>

      {rejectingId && (
        <RejectReasonModal
          onConfirm={(reason) => handleReject(rejectingId, reason)}
          onCancel={() => setRejectingId(null)}
        />
      )}
    </div>
  );
}
