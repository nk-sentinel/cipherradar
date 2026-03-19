import { useNavigate } from '@tanstack/react-router';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { usePortfolioSummary, useHeatMap } from '@/api/hooks/usePortfolio.ts';
import { useAuth } from '@/lib/auth.tsx';
import { cn, formatNumber } from '@/lib/utils.ts';
import type { HeatMapCell, SeverityLevel } from '@/mocks/data/portfolio.ts';

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  critical: 'var(--red)',
  high: 'var(--orange)',
  medium: 'var(--yellow)',
  low: 'var(--blue)',
  info: 'var(--text-3)',
};

const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED',
  low: 'LOW',
  info: 'INFO',
};

function heatCellColor(count: number, severity: SeverityLevel): string {
  if (count === 0) return 'var(--bg-3)';
  return SEVERITY_COLORS[severity];
}

function heatCellOpacity(count: number, max: number): number {
  if (count === 0) return 0.1;
  return 0.3 + 0.7 * (count / Math.max(max, 1));
}

function quantumRiskColor(score: number): string {
  if (score >= 70) return 'var(--red)';
  if (score >= 50) return 'var(--orange)';
  if (score >= 30) return 'var(--yellow)';
  return 'var(--green)';
}

function complianceColor(score: number): string {
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  if (score >= 40) return 'var(--orange)';
  return 'var(--red)';
}

export function PortfolioDashboard(): React.ReactElement {
  const { data: summary, isLoading: summaryLoading, error: summaryError } = usePortfolioSummary();
  const { data: heatMap, isLoading: heatMapLoading } = useHeatMap();
  const { user } = useAuth();
  const navigate = useNavigate();

  const isTeamManager = user?.role === 'team-manager';

  if (summaryLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (summaryError || !summary) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load dashboard data.
        </p>
      </div>
    );
  }

  const barData = summary.severityDistribution.map((s) => ({
    name: SEVERITY_LABELS[s.severity],
    count: s.count,
    fill: SEVERITY_COLORS[s.severity],
  }));

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
          Dashboard
          {isTeamManager && (
            <span
              style={{
                fontSize: '11px',
                color: 'var(--text-3)',
                fontWeight: 400,
                marginLeft: '8px',
              }}
            >
              (Team View)
            </span>
          )}
        </h1>
        <div className="topbar-right">
          <span>Last scan: {summary.lastScanTime}</span>
          <button className="btn btn-accent">+ New Scan</button>
        </div>
      </div>

      {/* 4 stat cards */}
      <div className="g4">
        <div className="stat">
          <div className="stat-label">Total Findings</div>
          <div className="stat-val" style={{ color: 'var(--accent)' }}>
            {formatNumber(summary.totalFindings)}
          </div>
          <div className="stat-sub">across {summary.totalRepos} repositories</div>
        </div>
        <div className="stat">
          <div className="stat-label">Critical + High</div>
          <div className="stat-val" style={{ color: 'var(--red)' }}>
            {summary.criticalPlusHigh}
          </div>
          <div className="stat-sub">{summary.affectedRepos} repos affected</div>
        </div>
        <div className="stat">
          <div className="stat-label">Quantum Exposed</div>
          <div className="stat-val" style={{ color: 'var(--orange)' }}>
            {summary.quantumExposed}
          </div>
          <div className="stat-sub">{summary.quantumExposedPercent}% of algorithms</div>
        </div>
        <div className="stat">
          <div className="stat-label">Compliance</div>
          <div className="stat-val" style={{ color: 'var(--yellow)' }}>
            {summary.complianceAvg}%
          </div>
          <div className="stat-sub">{summary.complianceFramework} avg</div>
        </div>
      </div>

      {/* Quantum readiness gauge + finding distribution */}
      <div className="g21">
        {/* Finding distribution bar chart */}
        <div className="card">
          <div className="card-title">Severity Distribution (All Repos)</div>
          <div style={{ width: '100%', height: 160 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fill: 'var(--text-3)', fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: 'var(--text-4)', fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-1)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    fontSize: '11px',
                    color: 'var(--text-1)',
                  }}
                />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {barData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Quantum readiness gauge */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div className="card-title" style={{ alignSelf: 'flex-start' }}>Quantum Readiness</div>
          <div
            data-testid="quantum-gauge"
            style={{
              fontSize: '56px',
              fontWeight: 700,
              color: quantumRiskColor(100 - summary.quantumReadinessPercent),
              fontVariantNumeric: 'tabular-nums',
              lineHeight: 1,
              marginTop: '8px',
            }}
          >
            {summary.quantumReadinessPercent}%
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '6px' }}>
            of algorithms are quantum-safe
          </div>
          <div
            className="progress"
            style={{ width: '80%', marginTop: '12px', height: '8px' }}
          >
            <div
              className="progress-fill"
              style={{
                width: `${String(summary.quantumReadinessPercent)}%`,
                background: quantumRiskColor(100 - summary.quantumReadinessPercent),
              }}
            />
          </div>
        </div>
      </div>

      {/* Heat map */}
      {!heatMapLoading && heatMap && (
        <div className="card">
          <div className="card-title">Severity Heat Map</div>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Repository</th>
                  {(['critical', 'high', 'medium', 'low', 'info'] as SeverityLevel[]).map((s) => (
                    <th key={s} style={{ textAlign: 'center' }}>{SEVERITY_LABELS[s]}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {heatMap.repos.map((repo) => {
                  const maxVal = Math.max(repo.critical, repo.high, repo.medium, repo.low, repo.info);
                  return (
                    <tr
                      key={repo.repoId}
                      className="clickable"
                      onClick={() =>
                        void navigate({
                          to: '/repos/$repoId/overview',
                          params: { repoId: repo.repoId },
                        })
                      }
                    >
                      <td>{repo.repoName}</td>
                      {(['critical', 'high', 'medium', 'low', 'info'] as SeverityLevel[]).map((s) => {
                        const count = repo[s as keyof HeatMapCell] as number;
                        return (
                          <td key={s} style={{ textAlign: 'center', padding: '6px' }}>
                            <div
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                width: '40px',
                                height: '28px',
                                borderRadius: 'var(--radius)',
                                background: heatCellColor(count, s),
                                opacity: heatCellOpacity(count, maxVal),
                                color: count > 0 ? '#fff' : 'var(--text-4)',
                                fontSize: '11px',
                                fontWeight: 600,
                              }}
                            >
                              {count}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Top 10 riskiest repos */}
      <div className="card">
        <div className="card-title">Top Riskiest Repositories</div>
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Provider</th>
              <th>Findings</th>
              <th>Critical</th>
              <th>Quantum Risk</th>
              <th>Compliance</th>
              <th>Last Scan</th>
            </tr>
          </thead>
          <tbody>
            {summary.topRiskRepos.map((repo) => (
              <tr
                key={repo.repoId}
                className="clickable"
                onClick={() =>
                  void navigate({
                    to: '/repos/$repoId/overview',
                    params: { repoId: repo.repoId },
                  })
                }
              >
                <td>
                  <strong>{repo.repoName}</strong>
                </td>
                <td>{repo.provider}</td>
                <td>{repo.findings}</td>
                <td>
                  <span
                    className={cn(
                      'badge',
                      repo.critical > 0 ? 'b-crit' : 'b-safe',
                    )}
                  >
                    {repo.critical}
                  </span>
                </td>
                <td style={{ color: quantumRiskColor(repo.quantumRisk) }}>
                  {repo.quantumRisk}
                </td>
                <td style={{ color: complianceColor(repo.compliancePercent) }}>
                  {repo.compliancePercent}%
                </td>
                <td>{repo.lastScan}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
