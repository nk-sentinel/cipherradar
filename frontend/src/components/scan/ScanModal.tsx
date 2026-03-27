import { useState } from 'react';
import { ScanSourceTabs, type SourceType } from './ScanSourceTabs';
import { useScanTrigger } from '@/api/hooks/useScanTrigger';

interface ScanModalProps {
  context: 'dashboard' | 'project-row' | 'project-overview';
  projectId?: string;
  defaultSourceType?: SourceType;
  onClose: () => void;
}

const BRANCHES = ['main', 'develop', 'staging', 'release/v1.0', 'feature/pqc-migration'];
const POLICIES = [
  { id: '', label: 'Default Policy' },
  { id: 'policy-nist', label: 'NIST 800-131A' },
  { id: 'policy-fips', label: 'FIPS 140-3' },
  { id: 'policy-pci', label: 'PCI-DSS 4.0' },
];

export function ScanModal({
  context,
  projectId,
  defaultSourceType = 'repository',
  onClose,
}: ScanModalProps): React.ReactElement {
  const [sourceType, setSourceType] = useState<SourceType>(defaultSourceType);
  const [branch, setBranch] = useState('main');
  const [policyId, setPolicyId] = useState('');
  const [containerTag, setContainerTag] = useState('');
  const [artifactVersion, setArtifactVersion] = useState('');
  const [projectInput, setProjectInput] = useState(projectId ?? '');
  const [expanded, setExpanded] = useState(false);

  const triggerMutation = useScanTrigger();

  const isSimplified = context === 'project-overview' && !expanded;

  function handleSubmit() {
    const resolvedProjectId = projectId ?? projectInput;
    if (!resolvedProjectId) return;

    triggerMutation.mutate(
      {
        projectId: resolvedProjectId,
        sourceType,
        branch: sourceType === 'repository' ? branch : undefined,
        policyId: policyId || undefined,
        containerTag: sourceType === 'container' ? containerTag : undefined,
        artifactVersion: sourceType === 'artifact' ? artifactVersion : undefined,
      },
      { onSuccess: () => onClose() },
    );
  }

  return (
    <div
      data-testid="scan-modal"
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
      <div
        className="card"
        style={{
          width: '480px',
          maxHeight: '90vh',
          overflow: 'auto',
          padding: '24px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-1)' }}>
            {isSimplified ? 'Quick Scan' : 'New Scan'}
          </h2>
          <button className="btn btn-outline" onClick={onClose} type="button" style={{ fontSize: '11px', padding: '4px 8px' }}>
            Close
          </button>
        </div>

        {/* Project ID display for prefilled contexts */}
        {(context === 'project-row' || context === 'project-overview') && projectId && (
          <div style={{ marginBottom: '12px' }}>
            <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
              Project
            </label>
            <div
              data-testid="project-id-display"
              style={{
                fontSize: '13px',
                color: 'var(--text-1)',
                padding: '6px 10px',
                background: 'var(--bg-2)',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border)',
              }}
            >
              {projectId}
            </div>
          </div>
        )}

        {/* Project input for dashboard context */}
        {context === 'dashboard' && (
          <div style={{ marginBottom: '12px' }}>
            <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
              Project ID
            </label>
            <input
              data-testid="project-id-input"
              type="text"
              value={projectInput}
              onChange={(e) => setProjectInput(e.target.value)}
              placeholder="Enter project ID..."
              style={{
                width: '100%',
                padding: '6px 10px',
                fontSize: '13px',
                background: 'var(--bg-2)',
                color: 'var(--text-1)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
              }}
            />
          </div>
        )}

        {/* Simplified view for project-overview */}
        {isSimplified ? (
          <>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
                Branch
              </label>
              <select
                data-testid="branch-selector"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
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
                {BRANCHES.map((b) => (
                  <option key={b} value={b}>{b}</option>
                ))}
              </select>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
                Policy
              </label>
              <select
                data-testid="policy-selector"
                value={policyId}
                onChange={(e) => setPolicyId(e.target.value)}
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
                {POLICIES.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
            </div>

            <button
              data-testid="more-options-btn"
              className="btn btn-outline"
              onClick={() => setExpanded(true)}
              type="button"
              style={{ width: '100%', marginBottom: '12px', fontSize: '12px' }}
            >
              More options
            </button>
          </>
        ) : (
          <>
            {/* Full 3-tab modal */}
            <ScanSourceTabs active={sourceType} onChange={setSourceType} />

            {sourceType === 'repository' && (
              <>
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
                    Branch
                  </label>
                  <select
                    data-testid="branch-selector"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
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
                    {BRANCHES.map((b) => (
                      <option key={b} value={b}>{b}</option>
                    ))}
                  </select>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
                    Policy
                  </label>
                  <select
                    data-testid="policy-selector"
                    value={policyId}
                    onChange={(e) => setPolicyId(e.target.value)}
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
                    {POLICIES.map((p) => (
                      <option key={p.id} value={p.id}>{p.label}</option>
                    ))}
                  </select>
                </div>
              </>
            )}

            {sourceType === 'container' && (
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
                  Container Image Tag
                </label>
                <input
                  data-testid="container-tag"
                  type="text"
                  value={containerTag}
                  onChange={(e) => setContainerTag(e.target.value)}
                  placeholder="e.g. myapp:latest"
                  style={{
                    width: '100%',
                    padding: '6px 10px',
                    fontSize: '13px',
                    background: 'var(--bg-2)',
                    color: 'var(--text-1)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                  }}
                />
              </div>
            )}

            {sourceType === 'artifact' && (
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
                  Artifact Version
                </label>
                <input
                  data-testid="artifact-version"
                  type="text"
                  value={artifactVersion}
                  onChange={(e) => setArtifactVersion(e.target.value)}
                  placeholder="e.g. 1.2.3"
                  style={{
                    width: '100%',
                    padding: '6px 10px',
                    fontSize: '13px',
                    background: 'var(--bg-2)',
                    color: 'var(--text-1)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                  }}
                />
              </div>
            )}
          </>
        )}

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            data-testid="scan-submit"
            className="btn btn-accent"
            onClick={handleSubmit}
            disabled={triggerMutation.isPending}
            type="button"
          >
            {triggerMutation.isPending ? 'Starting...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </div>
  );
}
