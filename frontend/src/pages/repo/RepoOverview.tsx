import { useNavigate, useParams } from '@tanstack/react-router';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { useRepository } from '@/api/hooks/useRepositories.ts';
import { cn } from '@/lib/utils.ts';

const CHART_COLORS = [
  'var(--blue)',
  'var(--red)',
  'var(--green)',
  'var(--orange)',
  'var(--yellow)',
  'var(--accent)',
  'var(--purple)',
  'var(--pink)',
];

function getCriticalBadgeClass(count: number): string {
  if (count >= 3) return 'b-crit';
  if (count >= 1) return 'b-high';
  return 'b-safe';
}

export function RepoOverview(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const navigate = useNavigate();
  const { data: repo, isLoading, error } = useRepository(repoId);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error || !repo) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load repository details.
        </p>
      </div>
    );
  }

  return (
    <div>
      <div className="topbar">
        <div className="repo-header">
          <h1>{repo.name}</h1>
          <span className="repo-provider">{repo.provider}</span>
        </div>
        <div className="topbar-right">
          <button className="btn btn-accent" onClick={() => alert('Scan triggered. This will be available when the backend scan API is integrated.')}>Scan Now</button>
          <button className="btn btn-outline" onClick={() => void navigate({ to: '/admin/settings' })}>Settings</button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="g4">
        <div className="stat">
          <div className="stat-label">Total Findings</div>
          <div className="stat-val" style={{ color: 'var(--accent)' }}>
            {repo.findings}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Critical</div>
          <div className="stat-val" style={{ color: 'var(--red)' }}>
            {repo.critical}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Quantum Risk</div>
          <div className="stat-val" style={{ color: 'var(--orange)' }}>
            {repo.quantumRisk}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Compliance</div>
          <div className="stat-val" style={{ color: 'var(--yellow)' }}>
            {repo.compliancePercent}%
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="g2">
        <div className="card">
          <div className="card-title">Algorithm Distribution</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={repo.algorithmDistribution}>
              <XAxis
                dataKey="name"
                tick={{ fontSize: 10, fill: 'var(--text-4)' }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis hide />
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
                {repo.algorithmDistribution.map((_entry, index) => (
                  <Cell
                    key={`cell-${String(index)}`}
                    fill={CHART_COLORS[index % CHART_COLORS.length] ?? 'var(--accent)'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">By Language</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {repo.languageBreakdown.map((lang) => (
              <div key={lang.language}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '12px',
                    marginBottom: '3px',
                  }}
                >
                  <span>{lang.language}</span>
                  <span style={{ color: 'var(--text-3)' }}>{lang.count}</span>
                </div>
                <div className="progress">
                  <div
                    className="progress-fill"
                    style={{
                      width: `${String(lang.percent)}%`,
                      background: 'var(--accent)',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent scans table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Recent Scans</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Scan #</th>
              <th>Branch</th>
              <th>Commit</th>
              <th>Findings</th>
              <th>Critical</th>
              <th>Duration</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {repo.recentScans.map((scan) => (
              <tr
                key={scan.id}
                className="clickable"
                style={{ cursor: 'pointer' }}
                onClick={() =>
                  void navigate({
                    to: '/repos/$repoId/scans/$scanId',
                    params: { repoId, scanId: String(scan.id) },
                  })
                }
              >
                <td>#{scan.id}</td>
                <td>{scan.branch}</td>
                <td>{scan.commit}</td>
                <td>{scan.findings}</td>
                <td>
                  <span className={cn('badge', getCriticalBadgeClass(scan.critical))}>
                    {scan.critical}
                  </span>
                </td>
                <td>{scan.duration}</td>
                <td>{scan.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
