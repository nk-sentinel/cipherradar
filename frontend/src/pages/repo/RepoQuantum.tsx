import { useParams } from '@tanstack/react-router';
import { useQuantumRiskForRepo } from '@/api/hooks/useQuantum.ts';
import { cn } from '@/lib/utils.ts';
import type { QuantumPriority } from '@/mocks/data/quantum.ts';

function priorityBadgeClass(p: QuantumPriority): string {
  switch (p) {
    case 'critical':
      return 'b-crit';
    case 'high':
      return 'b-high';
    case 'medium':
      return 'b-med';
    case 'low':
      return 'b-safe';
  }
}

function priorityLabel(p: QuantumPriority): string {
  switch (p) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Med';
    case 'low':
      return 'Low';
  }
}

function riskScoreColor(score: number): string {
  if (score >= 70) return 'var(--red)';
  if (score >= 50) return 'var(--orange)';
  if (score >= 30) return 'var(--yellow)';
  return 'var(--green)';
}

export function RepoQuantum(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const { data, isLoading, error } = useQuantumRiskForRepo(repoId);

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
          Failed to load quantum readiness data.
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
          Quantum Readiness
        </h1>
        <div className="topbar-right">
          <button className="btn btn-outline">Export PQC Report</button>
        </div>
      </div>

      {/* 3 stat cards */}
      <div className="g3">
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div
            className="stat-val"
            style={{ fontSize: '42px', color: riskScoreColor(data.riskScore) }}
          >
            {data.riskScore}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
            Quantum Risk Score
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '42px', color: 'var(--red)' }}>
            {data.vulnerableCount}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
            Vulnerable Algorithms
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '42px', color: 'var(--green)' }}>
            {data.safeCount}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
            Quantum-Safe Algorithms
          </div>
        </div>
      </div>

      {/* Migration Priority table */}
      <div className="card">
        <div className="card-title">Migration Priority</div>
        <table>
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Count</th>
              <th>Migrate To</th>
              <th>Priority</th>
            </tr>
          </thead>
          <tbody>
            {data.migrationPriorities.map((item) => (
              <tr key={item.algorithm}>
                <td>
                  <strong>{item.algorithm}</strong>
                </td>
                <td>{item.count}</td>
                <td>{item.migrateTo}</td>
                <td>
                  <span className={cn('badge', priorityBadgeClass(item.priority))}>
                    {priorityLabel(item.priority)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
