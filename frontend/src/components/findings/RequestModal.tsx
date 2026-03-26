import { useState } from 'react';
import { useCreateRequest, type RequestType, type ReasonCategory } from '@/api/hooks/useRequests';

interface RequestModalProps {
  findingId: string;
  defaultType: RequestType;
  onClose: () => void;
}

const REASON_CATEGORIES: { value: ReasonCategory; label: string }[] = [
  { value: 'compensating_control', label: 'Compensating Control' },
  { value: 'low_impact', label: 'Low Impact' },
  { value: 'migration_planned', label: 'Migration Planned' },
  { value: 'business_exception', label: 'Business Exception' },
];

export function RequestModal({
  findingId,
  defaultType,
  onClose,
}: RequestModalProps): React.ReactElement {
  const [type, setType] = useState<RequestType>(defaultType);
  const [justification, setJustification] = useState('');
  const [reasonCategory, setReasonCategory] = useState<ReasonCategory | ''>('');
  const [reviewDate, setReviewDate] = useState('');
  const [error, setError] = useState('');

  const createRequest = useCreateRequest();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!justification.trim()) {
      setError('Justification is required.');
      return;
    }

    if (type === 'risk_accepted' && !reasonCategory) {
      setError('Reason category is required for risk acceptance.');
      return;
    }

    createRequest.mutate(
      {
        findingId,
        type,
        justification: justification.trim(),
        reasonCategory: type === 'risk_accepted' ? (reasonCategory as ReasonCategory) : undefined,
        reviewDate: type === 'risk_accepted' && reviewDate ? reviewDate : undefined,
      },
      {
        onSuccess: () => {
          onClose();
        },
      },
    );
  };

  return (
    <div
      className="modal-overlay"
      data-testid="request-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal card" style={{ maxWidth: '500px', width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 700 }}>
            {type === 'false_positive' ? 'Request FP Review' : 'Request Risk Acceptance'}
          </h2>
          <button className="btn btn-outline" onClick={onClose} type="button">
            Close
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {/* Request type selector */}
          <div style={{ marginBottom: '12px' }}>
            <label className="field-label">Request Type</label>
            <select
              className="input"
              value={type}
              onChange={(e) => setType(e.target.value as RequestType)}
              data-testid="request-type-select"
            >
              <option value="false_positive">False Positive</option>
              <option value="risk_accepted">Risk Acceptance</option>
            </select>
          </div>

          {/* Justification */}
          <div style={{ marginBottom: '12px' }}>
            <label className="field-label">
              Justification <span style={{ color: 'var(--red)' }}>*</span>
            </label>
            <textarea
              className="input"
              style={{ minHeight: '80px', resize: 'vertical', width: '100%' }}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Explain why this finding should be marked as FP or risk accepted..."
              data-testid="request-justification"
            />
          </div>

          {/* Reason category (for RA only) */}
          {type === 'risk_accepted' && (
            <>
              <div style={{ marginBottom: '12px' }}>
                <label className="field-label">
                  Reason Category <span style={{ color: 'var(--red)' }}>*</span>
                </label>
                <select
                  className="input"
                  value={reasonCategory}
                  onChange={(e) => setReasonCategory(e.target.value as ReasonCategory | '')}
                  data-testid="request-reason-category"
                >
                  <option value="">Select a category...</option>
                  {REASON_CATEGORIES.map((cat) => (
                    <option key={cat.value} value={cat.value}>
                      {cat.label}
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label className="field-label">Review Date</label>
                <input
                  type="date"
                  className="input"
                  value={reviewDate}
                  onChange={(e) => setReviewDate(e.target.value)}
                  data-testid="request-review-date"
                />
              </div>
            </>
          )}

          {/* Error message */}
          {error && (
            <div
              className="alert alert-warn"
              style={{ marginBottom: '12px' }}
              data-testid="request-error"
            >
              {error}
            </div>
          )}

          {/* Submit */}
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button className="btn btn-outline" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn btn-accent"
              type="submit"
              disabled={createRequest.isPending}
              data-testid="request-submit"
            >
              {createRequest.isPending ? 'Submitting...' : 'Submit Request'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
