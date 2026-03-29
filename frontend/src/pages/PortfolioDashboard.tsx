import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { usePortfolioSummary, useHeatMap } from '@/api/hooks/usePortfolio.ts';
import { useAuth } from '@/lib/auth.tsx';
import { cn, formatNumber } from '@/lib/utils.ts';
import { ScanModal } from '@/components/scan/ScanModal';
import { apiClient } from '@/api/client.ts';
import type { HeatMapCell, SeverityLevel } from '@/mocks/data/portfolio.ts';

interface AssignedFinding {
  id: string;
  severity: SeverityLevel;
  projectName: string;
  finding: string;
  status: string;
}

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
  const [scanModalOpen, setScanModalOpen] = useState(false);

  const isTeamManager = user?.role === 'team-manager';
  const showAssigned = user?.role === 'developer' || user?.role === 'team-manager';
  const { data: assignedFindings, isLoading: assignedLoading } = useQuery({
    queryKey: ['my-assigned-findings'],
    queryFn: () => apiClient<AssignedFinding[]>('/findings?assigned_to=me&status=open,in_review,in_progress'),
    enabled: showAssigned,
  });

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

  // Fresh org — no projects or findings yet. Show welcome state.
  const isEmpty = (summary.totalRepos ?? 0) === 0 && (summary.totalFindings ?? 0) === 0;
  if (isEmpty) {
    return (
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 700, letterSpacing: '0.04em', marginBottom: '24px' }}>Dashboard</h1>
        <div className="card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔐</div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-0)' }}>
            Welcome to CipherRadar
          </h2>
          <p style={{ color: 'var(--text-2)', fontSize: '14px', maxWidth: '480px', margin: '0 auto 24px', lineHeight: 1.6 }}>
            Get started by connecting your code repositories. Once you import projects
            and run your first scan, your cryptographic findings and compliance posture
            will appear here.
          </p>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              onClick={() => void navigate({ to: '/admin/integrations' })}
              style={{ fontSize: '13px', padding: '8px 20px' }}
            >
              Connect a Git Provider
            </button>
            <button
              className="btn btn-outline"
              onClick={() => void navigate({ to: '/repos' })}
              style={{ fontSize: '13px', padding: '8px 20px' }}
            >
              Import Projects
            </button>
            <button
              className="btn btn-outline"
              onClick={() => void navigate({ to: '/admin/settings' })}
              style={{ fontSize: '13px', padding: '8px 20px' }}
            >
              Configure Settings
            </button>
          </div>
          <div style={{ marginTop: '32px', padding: '16px', background: 'var(--bg-2)', borderRadius: '8px', maxWidth: '400px', margin: '32px auto 0' }}>
            <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '8px' }}>Quick start:</p>
            <div style={{ fontSize: '12px', color: 'var(--text-1)', textAlign: 'left', lineHeight: 1.8 }}>
              <div>1. Connect your GitHub, GitLab, or Bitbucket account</div>
              <div>2. Import repositories as projects</div>
              <div>3. Run your first cryptographic scan</div>
              <div>4. Review findings and compliance posture</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const barData = (summary.severityDistribution ?? []).map((s) => ({
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
          <span>Last scan: {summary.lastScanTime ?? 'N/A'}</span>
          <button
            className="btn btn-accent"
            onClick={() => setScanModalOpen(true)}
          >
            + New Scan
          </button>
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

      {/* Heat map — the useHeatMap hook normalises API { groups } to { repos } */}
      {!heatMapLoading && heatMap && heatMap.repos && heatMap.repos.length > 0 && (
        <div className="card">
          <div className="card-title">Severity Heat Map</div>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th scope="col">Group</th>
                  {(['critical', 'high', 'medium', 'low', 'info'] as SeverityLevel[]).map((s) => (
                    <th scope="col" key={s} style={{ textAlign: 'center' }}>{SEVERITY_LABELS[s]}</th>
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

      {/* My Assigned Findings — for DEV and TM roles */}
      {showAssigned && (
        <div className="card" data-testid="my-assigned-findings">
          <div className="card-title">My Assigned Findings</div>
          <p style={{ color: 'var(--text-3)', fontSize: '12px', marginBottom: '8px' }}>
            Findings assigned to you across all projects.
          </p>
          <table>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Project</th>
                <th scope="col">Finding</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {assignedLoading ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-3)' }}>
                    Loading...
                  </td>
                </tr>
              ) : assignedFindings && assignedFindings.length > 0 ? (
                assignedFindings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span
                        className={cn(
                          'badge',
                          f.severity === 'critical' ? 'b-crit' :
                          f.severity === 'high' ? 'b-high' :
                          f.severity === 'medium' ? 'b-med' : 'b-low',
                        )}
                      >
                        {SEVERITY_LABELS[f.severity]}
                      </span>
                    </td>
                    <td>{f.projectName}</td>
                    <td>{f.finding}</td>
                    <td>{f.status}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-3)' }}>
                    No findings assigned to you.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Top 10 riskiest repos */}
      <div className="card">
        <div className="card-title">Top Riskiest Repositories</div>
        <table>
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Provider</th>
              <th scope="col">Findings</th>
              <th scope="col">Critical</th>
              <th scope="col">Quantum Risk</th>
              <th scope="col">Compliance</th>
              <th scope="col">Last Scan</th>
            </tr>
          </thead>
          <tbody>
            {((summary.topRiskRepos ?? (summary as unknown as Record<string, unknown[]>).heatMap ?? []) as unknown as Record<string, unknown>[]).map((repo) => (
              <tr
                key={String(repo.repoId ?? repo.projectId ?? '')}
                className="clickable"
                onClick={() =>
                  void navigate({
                    to: '/repos/$repoId/overview',
                    params: { repoId: String(repo.repoId ?? repo.projectId ?? '') },
                  })
                }
              >
                <td>
                  <strong>{String(repo.repoName ?? repo.projectName ?? '')}</strong>
                </td>
                <td>{String(repo.provider ?? '—')}</td>
                <td>{String(repo.findings ?? (Number(repo.critical ?? 0) + Number(repo.high ?? 0) + Number(repo.medium ?? 0) + Number(repo.low ?? 0)))}</td>
                <td>
                  <span
                    className={cn(
                      'badge',
                      Number(repo.critical ?? 0) > 0 ? 'b-crit' : 'b-safe',
                    )}
                  >
                    {String(repo.critical ?? 0)}
                  </span>
                </td>
                <td style={{ color: quantumRiskColor(Number(repo.quantumRisk ?? 0)) }}>
                  {String(repo.quantumRisk ?? '—')}
                </td>
                <td style={{ color: complianceColor(Number(repo.compliancePercent ?? 0)) }}>
                  {String(repo.compliancePercent ?? '—')}%
                </td>
                <td>{String(repo.lastScan ?? '—')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {scanModalOpen && (
        <ScanModal context="dashboard" onClose={() => setScanModalOpen(false)} />
      )}
    </div>
  );
}
