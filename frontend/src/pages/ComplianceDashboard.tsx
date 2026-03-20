import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useComplianceDashboard } from '@/api/hooks/useComplianceDashboard.ts';
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

const MONTH_LABELS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const FRAMEWORK_COLORS: Record<string, string> = {
  'nist-800-131a': '#3b82f6',
  'fips-140-3': '#f59e0b',
  'pci-dss-v4': '#8b5cf6',
  'cnsa-2': '#ef4444',
  'iso-27001-a8-24': '#10b981',
  'eu-cra': '#ec4899',
};

/* ---------- component ---------- */

export function ComplianceDashboard(): React.ReactElement {
  const { data, isLoading, error } = useComplianceDashboard();
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
          Failed to load compliance dashboard data.
        </p>
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
  const barChartData = data.repoComparison.map((repo) => ({
    name: repo.repoName,
    ...repo.scores,
  }));

  const selectedFw = selectedFramework
    ? data.frameworks.find((fw) => fw.id === selectedFramework)
    : null;

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
          Compliance Dashboard
        </h1>
        <div className="topbar-right">
          <button className="btn btn-outline">Download Gap Report (PDF)</button>
        </div>
      </div>

      {/* 6 Framework Score Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '12px',
          marginBottom: '16px',
        }}
      >
        {data.frameworks.map((fw) => (
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
            {data.cnsaTimeline.map((item, idx) => (
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
                    {idx < data.cnsaTimeline.length - 1 && (
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
                {data.frameworks.map((fw) => (
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

      {/* Compliance by Repository table */}
      <div className="card" style={{ marginTop: '16px' }}>
        <div className="card-title">Compliance by Repository</div>
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              {data.frameworks.map((fw) => (
                <th key={fw.id}>{fw.shortName}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.repoComparison.map((repo) => (
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
                {data.frameworks.map((fw) => {
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
      </div>
    </div>
  );
}
