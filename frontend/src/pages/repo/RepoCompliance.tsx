import { useParams } from '@tanstack/react-router';
import { useComplianceForRepo } from '@/api/hooks/useCompliance.ts';
import { cn } from '@/lib/utils.ts';
import type { ComplianceStatus } from '@/mocks/data/compliance.ts';

function scoreColor(score: number): string {
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  if (score >= 40) return 'var(--orange)';
  return 'var(--red)';
}

function statusBadgeClass(status: ComplianceStatus): string {
  switch (status) {
    case 'disallowed':
      return 'b-crit';
    case 'deprecated':
      return 'b-high';
    case 'acceptable':
      return 'b-safe';
  }
}

function statusLabel(status: ComplianceStatus): string {
  switch (status) {
    case 'disallowed':
      return 'Disallowed';
    case 'deprecated':
      return 'Deprecated';
    case 'acceptable':
      return 'Acceptable';
  }
}

export function RepoCompliance(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const { data, isLoading, error } = useComplianceForRepo(repoId);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load compliance data.
        </p>
      </div>
    );
  }

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
          Compliance
        </h1>
        <div className="topbar-right">
          <button
            className="btn btn-outline"
            disabled
            title="Coming soon"
            style={{ opacity: 0.5, cursor: 'not-allowed' }}
          >
            Download Gap Report
          </button>
        </div>
      </div>

      {/* 3 framework cards */}
      <div className="g3">
        {(data.frameworks ?? []).map((fw) => (
          <div
            key={fw.framework}
            className="card"
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600 }}>{fw.framework}</div>
              <div className="progress" style={{ width: '120px', marginTop: '6px' }}>
                <div
                  className="progress-fill"
                  style={{
                    width: `${String(fw.score)}%`,
                    background: scoreColor(fw.score),
                  }}
                />
              </div>
            </div>
            <div
              style={{
                fontSize: '28px',
                fontWeight: 700,
                color: scoreColor(fw.score),
              }}
            >
              {fw.score}%
            </div>
          </div>
        ))}
      </div>

      {/* Non-Compliant Findings table */}
      <div className="card">
        <div className="card-title">Non-Compliant Findings (NIST 800-131A)</div>
        <table>
          <thead>
            <tr>
              <th scope="col">Status</th>
              <th scope="col">Algorithm</th>
              <th scope="col">Classification</th>
              <th scope="col">Count</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {(data.nonCompliantItems ?? []).map((item) => (
              <tr key={`${item.algorithm}-${item.status}`}>
                <td>
                  <span className={cn('badge', statusBadgeClass(item.status))}>
                    {statusLabel(item.status)}
                  </span>
                </td>
                <td>{item.algorithm}</td>
                <td>{item.classification}</td>
                <td>{item.count}</td>
                <td>{item.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
