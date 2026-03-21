import { useNavigate } from '@tanstack/react-router';
import { useCompliance } from '@/api/hooks/useCompliance.ts';

function scoreColor(score: number): string {
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  if (score >= 40) return 'var(--orange)';
  return 'var(--red)';
}

export function Compliance(): React.ReactElement {
  const { data, isLoading, error } = useCompliance();
  const navigate = useNavigate();

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
          Compliance (Portfolio)
        </h1>
        <div className="topbar-right">
          <button
            className="btn btn-outline"
            onClick={() => window.open('/api/v1/reports/compliance-gap?format=pdf', '_blank')}
          >
            Download Gap Report (PDF)
          </button>
        </div>
      </div>

      {/* 3 framework cards */}
      <div className="g3">
        {data.frameworks.map((fw) => (
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
              {fw.description && (
                <div style={{ fontSize: '11px', color: 'var(--text-3)' }}>{fw.description}</div>
              )}
              <div className="progress" style={{ width: '140px', marginTop: '6px' }}>
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
                fontSize: '32px',
                fontWeight: 700,
                color: scoreColor(fw.score),
              }}
            >
              {fw.score}%
            </div>
          </div>
        ))}
      </div>

      {/* Compliance by Repository table */}
      <div className="card">
        <div className="card-title">Compliance by Repository</div>
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>NIST 800-131A</th>
              <th>FIPS 140-3</th>
              <th>CNSA 2.0</th>
              <th>Disallowed</th>
            </tr>
          </thead>
          <tbody>
            {data.repoCompliance.map((repo) => (
              <tr
                key={repo.repoId}
                className="clickable"
                onClick={() =>
                  void navigate({
                    to: '/repos/$repoId/compliance',
                    params: { repoId: repo.repoId },
                  })
                }
              >
                <td>{repo.repoName}</td>
                <td style={{ color: scoreColor(repo.nist) }}>{repo.nist}%</td>
                <td style={{ color: scoreColor(repo.fips) }}>{repo.fips}%</td>
                <td style={{ color: scoreColor(repo.cnsa) }}>{repo.cnsa}%</td>
                <td>{repo.disallowed}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
