import { useState } from 'react';
import { useEnvironments, usePromote } from '@/api/hooks/useProvenance';

interface PromoteModalProps {
  scanId: string;
  currentEnvironment: string;
  onClose: () => void;
}

export function PromoteModal({ scanId, currentEnvironment, onClose }: PromoteModalProps): React.ReactElement {
  const { data: environments } = useEnvironments();
  const promoteMutation = usePromote();
  const [selectedEnv, setSelectedEnv] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);

  const availableEnvs = (environments ?? []).filter(
    (env) => env.name !== currentEnvironment,
  );

  function handlePromote() {
    if (!selectedEnv) return;
    if (!showConfirm) {
      setShowConfirm(true);
      return;
    }
    promoteMutation.mutate(
      { scanId, environment: selectedEnv },
      { onSuccess: () => onClose() },
    );
  }

  return (
    <div
      data-testid="promote-modal"
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
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="card" style={{ width: '380px', padding: '24px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-1)', marginBottom: '16px' }}>
          Promote Scan
        </h2>

        <div style={{ marginBottom: '12px' }}>
          <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
            Current Environment
          </label>
          <div style={{ fontSize: '13px', color: 'var(--text-1)', fontWeight: 600 }}>
            {currentEnvironment}
          </div>
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
            Promote to...
          </label>
          <select
            data-testid="promote-target"
            value={selectedEnv}
            onChange={(e) => { setSelectedEnv(e.target.value); setShowConfirm(false); }}
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: '13px',
              background: 'var(--bg-2)',
              color: 'var(--text-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
            }}
          >
            <option value="">Select environment...</option>
            {availableEnvs.map((env) => (
              <option key={env.id} value={env.name} data-testid={`env-option-${env.name}`}>
                {env.label}
              </option>
            ))}
          </select>
        </div>

        {showConfirm && selectedEnv && (
          <div
            data-testid="promote-confirmation"
            style={{
              padding: '12px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid var(--amber)',
              borderRadius: 'var(--radius)',
              marginBottom: '16px',
              fontSize: '12px',
              color: 'var(--text-1)',
            }}
          >
            Are you sure you want to promote this scan from <strong>{currentEnvironment}</strong> to <strong>{selectedEnv}</strong>?
            Click "Confirm Promote" to proceed.
          </div>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            data-testid="promote-submit"
            className="btn btn-accent"
            onClick={handlePromote}
            disabled={!selectedEnv || promoteMutation.isPending}
            type="button"
          >
            {promoteMutation.isPending
              ? 'Promoting...'
              : showConfirm
                ? 'Confirm Promote'
                : 'Promote'}
          </button>
        </div>
      </div>
    </div>
  );
}
