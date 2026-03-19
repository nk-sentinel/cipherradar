import { useNavigate } from '@tanstack/react-router';
import { useQuantumRisk } from '@/api/hooks/useQuantum.ts';
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

export function QuantumReadiness(): React.ReactElement {
  const { data, isLoading, error } = useQuantumRisk();
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
          Failed to load quantum readiness data.
        </p>
      </div>
    );
  }

  const { statusBreakdown } = data;
  const total = statusBreakdown.vulnerable + statusBreakdown.safe + statusBreakdown.unknown + statusBreakdown.broken;

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
          Quantum Readiness (Portfolio)
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
            style={{ fontSize: '48px', color: riskScoreColor(data.riskScore) }}
          >
            {data.riskScore}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            Org Quantum Risk Score
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '48px', color: 'var(--red)' }}>
            {data.vulnerableCount}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            Vulnerable Algorithms
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '48px', color: 'var(--orange)' }}>
            {data.migrationEffort}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            Est. Migration Effort
          </div>
        </div>
      </div>

      <div className="g2">
        {/* Migration Priority table */}
        <div className="card">
          <div className="card-title">Migration Priority (All Repos)</div>
          <table>
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Count</th>
                <th>Repos</th>
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
                  <td>{item.repos}</td>
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

        {/* Quantum Status Breakdown + Risk by Repo */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {/* Quantum Status Breakdown */}
          <div className="card">
            <div className="card-title">Quantum Status Breakdown</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <StatusBar
                label="Vulnerable"
                value={statusBreakdown.vulnerable}
                total={total}
                color="var(--red)"
              />
              <StatusBar
                label="Safe"
                value={statusBreakdown.safe}
                total={total}
                color="var(--green)"
              />
              <StatusBar
                label="Unknown"
                value={statusBreakdown.unknown}
                total={total}
                color="var(--yellow)"
              />
              <StatusBar
                label="Broken"
                value={statusBreakdown.broken}
                total={total}
                color="var(--orange)"
              />
            </div>
          </div>

          {/* Risk by Repository */}
          <div className="card">
            <div className="card-title">Risk by Repository</div>
            <table>
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Risk Score</th>
                  <th>Vulnerable</th>
                  <th>Safe</th>
                </tr>
              </thead>
              <tbody>
                {data.repoRisks.map((repo) => (
                  <tr
                    key={repo.repoId}
                    className="clickable"
                    onClick={() =>
                      void navigate({
                        to: '/repos/$repoId/quantum',
                        params: { repoId: repo.repoId },
                      })
                    }
                  >
                    <td>{repo.repoName}</td>
                    <td style={{ color: riskScoreColor(repo.riskScore) }}>{repo.riskScore}</td>
                    <td>{repo.vulnerable}</td>
                    <td>{repo.safe}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusBar({
  label,
  value,
  total,
  color,
}: {
  label: string;
  value: number;
  total: number;
  color: string;
}): React.ReactElement {
  const percent = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: '12px',
          marginBottom: '3px',
        }}
      >
        <span>{label}</span>
        <span style={{ color: 'var(--text-3)' }}>{percent}%</span>
      </div>
      <div className="progress">
        <div
          className="progress-fill"
          style={{ width: `${String(percent)}%`, background: color }}
        />
      </div>
    </div>
  );
}
