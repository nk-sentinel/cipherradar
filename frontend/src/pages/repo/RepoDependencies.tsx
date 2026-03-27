import { useParams } from '@tanstack/react-router';

export function RepoDependencies(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}
      >
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
            letterSpacing: '0.04em',
          }}
        >
          Dependencies
        </h1>
        <div className="topbar-right">
          <button
            className="btn btn-outline"
            disabled
            title="Coming soon"
            style={{ opacity: 0.5, cursor: 'not-allowed' }}
          >
            Import SBOM
          </button>
        </div>
      </div>

      <div className="g3">
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '42px', color: 'var(--accent)' }}>
            --
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
            Total Dependencies
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '42px', color: 'var(--orange)' }}>
            --
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
            With Crypto Usage
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '42px', color: 'var(--red)' }}>
            --
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
            Vulnerable
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Dependency List</div>
        <p style={{ color: 'var(--text-3)', fontSize: '13px', padding: '20px 0' }}>
          SBOM integration coming soon. Upload an SBOM or enable auto-detection for project{' '}
          <strong>{repoId}</strong> to see dependency-level crypto analysis.
        </p>
      </div>
    </div>
  );
}
