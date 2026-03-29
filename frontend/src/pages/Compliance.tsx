import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useCompliance } from '@/api/hooks/useCompliance.ts';
import { useComplianceDashboard } from '@/api/hooks/useComplianceDashboard.ts';
import { useQuantumRisk } from '@/api/hooks/useQuantum.ts';
import { PQCMigrationProgress } from '@/components/compliance/PQCMigrationProgress.tsx';
import { cn } from '@/lib/utils.ts';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import type { FrameworkScoreCard, CNSATimelineItem } from '@/mocks/data/complianceDashboard.ts';
import type { QuantumPriority } from '@/mocks/data/quantum.ts';

/* ---------- helpers ---------- */

function scoreColor(score: number): string {
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  if (score >= 40) return 'var(--orange)';
  return 'var(--red)';
}

function statusColor(status: CNSATimelineItem['status']): string {
  switch (status) {
    case 'completed':
      return 'var(--green)';
    case 'in-progress':
      return 'var(--yellow)';
    case 'upcoming':
      return 'var(--text-3)';
    case 'overdue':
      return 'var(--red)';
  }
}

function statusBadgeClass(status: CNSATimelineItem['status']): string {
  switch (status) {
    case 'completed':
      return 'b-safe';
    case 'in-progress':
      return 'b-med';
    case 'upcoming':
      return 'b-high';
    case 'overdue':
      return 'b-crit';
  }
}

function trendDelta(fw: FrameworkScoreCard): React.ReactElement {
  const diff = fw.score - fw.previousScore;
  const positive = diff >= 0;
  return (
    <span
      style={{
        fontSize: '11px',
        color: positive ? 'var(--green)' : 'var(--red)',
        fontWeight: 600,
      }}
    >
      {positive ? '+' : ''}{diff}% from last period
    </span>
  );
}

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

const MONTH_LABELS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const FRAMEWORK_COLORS: Record<string, string> = {
  'nist-800-131a': '#3b82f6',
  'fips-140-3': '#f59e0b',
  'pci-dss-v4': '#8b5cf6',
  'cnsa-2': '#ef4444',
  'iso-27001-a8-24': '#10b981',
  'eu-cra': '#ec4899',
};

/* ---------- sub-components ---------- */

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

/* ---------- main component ---------- */

export function Compliance(): React.ReactElement {
  const { data, isLoading, error } = useCompliance();
  const { data: dashData, isLoading: dashLoading, error: dashError } = useComplianceDashboard();
  const { data: quantumData, isLoading: quantumLoading, error: quantumError } = useQuantumRisk();
  const navigate = useNavigate();
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

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

  // Fresh org — no compliance data yet
  const isEmpty = (data.frameworks ?? []).length === 0;
  if (isEmpty) {
    return (
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 700, letterSpacing: '0.04em', marginBottom: '24px' }}>
          Compliance (Portfolio)
        </h1>
        <div className="card" style={{ textAlign: 'center', padding: '48px 24px' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>📋</div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-0)' }}>
            No compliance data yet
          </h2>
          <p style={{ color: 'var(--text-2)', fontSize: '14px', maxWidth: '480px', margin: '0 auto', lineHeight: 1.6 }}>
            Compliance posture will appear here once you&apos;ve imported projects and run scans
            with framework analysis enabled (NIST, FIPS, PCI-DSS, CNSA 2.0, ISO 27001, EU CRA).
          </p>
        </div>
      </div>
    );
  }

  /* sparkline data per framework */
  const sparklineData = (fw: FrameworkScoreCard) =>
    fw.trend.map((val, idx) => ({
      month: MONTH_LABELS[idx],
      score: val,
    }));

  /* cross-repo bar chart data */
  const barChartData = dashData
    ? (dashData.repoComparison ?? []).map((repo) => ({
        name: repo.repoName,
        ...repo.scores,
      }))
    : [];

  const selectedFw = selectedFramework && dashData
    ? (dashData.frameworks ?? []).find((fw) => fw.id === selectedFramework)
    : null;

  /* quantum status breakdown */
  const statusBreakdown = quantumData?.statusBreakdown ?? { vulnerable: 0, safe: 0, unknown: 0, broken: 0 };
  const quantumTotal = (statusBreakdown.vulnerable ?? 0) + (statusBreakdown.safe ?? 0) + (statusBreakdown.unknown ?? 0) + (statusBreakdown.broken ?? 0);

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

      {/* 3 framework cards (original) */}
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

      {/* PQC Migration Progress */}
      <PQCMigrationProgress />

      {/* Compliance by Repository table */}
      <div className="card">
        <div className="card-title">Compliance by Repository</div>
        <table>
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">NIST 800-131A</th>
              <th scope="col">FIPS 140-3</th>
              <th scope="col">CNSA 2.0</th>
              <th scope="col">Disallowed</th>
            </tr>
          </thead>
          <tbody>
            {(data.repoCompliance ?? []).map((repo) => (
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

      {/* ====== Compliance Dashboard section (merged from NAV-2) ====== */}
      {dashLoading && (
        <div className="card" style={{ marginTop: '16px' }}>
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading framework trends...</p>
        </div>
      )}
      {!dashLoading && (dashError || !dashData) && (
        <div className="card" style={{ marginTop: '16px' }}>
          <div className="card-title">Framework Trends</div>
          <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
            No framework data available. Compliance trend data will appear here once scans have been run with framework analysis enabled.
          </p>
        </div>
      )}
      {!dashLoading && !dashError && dashData && (
        <>
          <h2
            style={{
              fontSize: '16px',
              fontWeight: 700,
              marginTop: '32px',
              marginBottom: '16px',
              textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
              letterSpacing: '0.04em',
            }}
          >
            Framework Trends
          </h2>

          {/* 6 Framework Score Cards with sparklines */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '12px',
              marginBottom: '16px',
            }}
          >
            {(dashData.frameworks ?? []).map((fw) => (
              <div
                key={fw.id}
                className="card"
                style={{
                  cursor: 'pointer',
                  border: selectedFramework === fw.id ? '1px solid var(--accent)' : undefined,
                }}
                onClick={() => setSelectedFramework(selectedFramework === fw.id ? null : fw.id)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 600 }}>{fw.framework}</div>
                    <div style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
                      {fw.description}
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
                <div className="progress" style={{ marginTop: '8px' }}>
                  <div
                    className="progress-fill"
                    style={{
                      width: `${String(fw.score)}%`,
                      background: scoreColor(fw.score),
                    }}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px' }}>
                  {trendDelta(fw)}
                  <span style={{ fontSize: '10px', color: 'var(--text-4)' }}>
                    {fw.compliantFindings}/{fw.totalFindings} compliant
                  </span>
                </div>
                {/* Sparkline */}
                <div style={{ marginTop: '8px', height: '40px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData(fw)}>
                      <Area
                        type="monotone"
                        dataKey="score"
                        stroke={FRAMEWORK_COLORS[fw.id] ?? 'var(--accent)'}
                        fill={FRAMEWORK_COLORS[fw.id] ?? 'var(--accent)'}
                        fillOpacity={0.15}
                        strokeWidth={1.5}
                        dot={false}
                        isAnimationActive={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            ))}
          </div>

          {/* Drill-down if selected */}
          {selectedFw && (
            <div className="card" style={{ marginBottom: '16px' }}>
              <div className="card-title">{selectedFw.framework} - Detail Trend</div>
              <div style={{ height: '200px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={sparklineData(selectedFw)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                    <XAxis dataKey="month" tick={{ fontSize: 10, fill: 'var(--text-3)' }} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--text-3)' }} />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--bg-2)',
                        border: '1px solid var(--border)',
                        fontSize: '11px',
                        color: 'var(--text-1)',
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke={FRAMEWORK_COLORS[selectedFw.id] ?? 'var(--accent)'}
                      fill={FRAMEWORK_COLORS[selectedFw.id] ?? 'var(--accent)'}
                      fillOpacity={0.2}
                      strokeWidth={2}
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-3)' }}>
                Click a repository below to see findings filtered by {selectedFw.framework}.
              </div>
            </div>
          )}

          <div className="g2">
            {/* CNSA 2.0 Timeline */}
            <div className="card">
              <div className="card-title">CNSA 2.0 Migration Timeline</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {(dashData.cnsaTimeline ?? []).map((item, idx) => (
                  <div key={item.id}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                      {/* timeline dot + line */}
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '20px' }}>
                        <div
                          style={{
                            width: '12px',
                            height: '12px',
                            borderRadius: '50%',
                            background: statusColor(item.status),
                            border: '2px solid var(--bg-2)',
                            flexShrink: 0,
                          }}
                        />
                        {idx < (dashData.cnsaTimeline ?? []).length - 1 && (
                          <div
                            style={{
                              width: '2px',
                              height: '30px',
                              background: 'var(--border)',
                              marginTop: '2px',
                            }}
                          />
                        )}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontSize: '12px', fontWeight: 600 }}>{item.label}</div>
                          <span className={cn('badge', statusBadgeClass(item.status))}>
                            {item.status}
                          </span>
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
                          Deadline: {new Date(item.deadline).toLocaleDateString('en-US', { month: 'short', year: 'numeric' })}
                        </div>
                        <div className="progress" style={{ marginTop: '4px', height: '4px' }}>
                          <div
                            className="progress-fill"
                            style={{
                              width: `${String(item.progress)}%`,
                              background: statusColor(item.status),
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Cross-repo comparison bar chart */}
            <div className="card">
              <div className="card-title">Cross-Repository Comparison</div>
              <div style={{ height: '320px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={barChartData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                    <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--text-3)' }} />
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-2)' }} width={110} />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--bg-2)',
                        border: '1px solid var(--border)',
                        fontSize: '11px',
                        color: 'var(--text-1)',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '10px' }} />
                    {(dashData.frameworks ?? []).map((fw) => (
                      <Bar
                        key={fw.id}
                        dataKey={fw.id}
                        name={fw.shortName}
                        fill={FRAMEWORK_COLORS[fw.id] ?? 'var(--accent)'}
                        radius={[0, 2, 2, 0]}
                        isAnimationActive={false}
                      />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Extended Compliance by Repository table (from dashboard) */}
          <div className="card" style={{ marginTop: '16px' }}>
            <div className="card-title">All Frameworks by Repository</div>
            {(dashData.repoComparison ?? []).length === 0 ? (
              <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
                No framework data available.
              </p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Repository</th>
                    {(dashData.frameworks ?? []).map((fw) => (
                      <th scope="col" key={fw.id}>{fw.shortName}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(dashData.repoComparison ?? []).map((repo) => (
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
                      <td><strong>{repo.repoName}</strong></td>
                      {(dashData.frameworks ?? []).map((fw) => {
                        const score = repo.scores[fw.id] ?? 0;
                        return (
                          <td key={fw.id} style={{ color: scoreColor(score) }}>
                            {score}%
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}

      {/* ====== Quantum Readiness section (merged from NAV-1) ====== */}
      <h2
        style={{
          fontSize: '16px',
          fontWeight: 700,
          marginTop: '32px',
          marginBottom: '16px',
          textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
          letterSpacing: '0.04em',
        }}
      >
        Quantum Readiness
      </h2>

      {quantumLoading && (
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading quantum data...</p>
        </div>
      )}

      {quantumError && (
        <div className="card">
          <p style={{ color: 'var(--red)', fontSize: '13px' }}>
            Failed to load quantum readiness data.
          </p>
        </div>
      )}

      {!quantumLoading && !quantumError && quantumData && (
        <>
          {/* 3 quantum stat cards */}
          <div className="g3">
            <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
              <div
                className="stat-val"
                style={{ fontSize: '48px', color: riskScoreColor(quantumData.riskScore) }}
              >
                {quantumData.riskScore}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
                Org Quantum Risk Score
              </div>
            </div>
            <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
              <div className="stat-val" style={{ fontSize: '48px', color: 'var(--red)' }}>
                {quantumData.vulnerableCount}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
                Vulnerable Algorithms
              </div>
            </div>
            <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
              <div className="stat-val" style={{ fontSize: '48px', color: 'var(--orange)' }}>
                {quantumData.migrationEffort}
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
                  {(quantumData.migrationPriorities ?? []).map((item) => (
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
                    total={quantumTotal}
                    color="var(--red)"
                  />
                  <StatusBar
                    label="Safe"
                    value={statusBreakdown.safe}
                    total={quantumTotal}
                    color="var(--green)"
                  />
                  <StatusBar
                    label="Unknown"
                    value={statusBreakdown.unknown}
                    total={quantumTotal}
                    color="var(--yellow)"
                  />
                  <StatusBar
                    label="Broken"
                    value={statusBreakdown.broken}
                    total={quantumTotal}
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
                    {(quantumData.repoRisks ?? []).map((repo) => (
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
        </>
      )}
    </div>
  );
}
