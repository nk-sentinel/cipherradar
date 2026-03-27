import { usePQCMigration } from '@/api/hooks/usePQCMigration.ts';
import type { AlgorithmFamilyProgress, LaggingProject } from '@/api/hooks/usePQCMigration.ts';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

/* ---------- helpers ---------- */

const DONUT_COLORS: Record<string, string> = {
  Vulnerable: '#ef4444',   // red
  Safe: '#22c55e',         // green
  Unknown: '#6b7280',      // gray
};

function migrationBarColor(percent: number): string {
  if (percent >= 80) return 'var(--green)';
  if (percent >= 50) return 'var(--yellow)';
  if (percent >= 20) return 'var(--orange)';
  return 'var(--red)';
}

/* ---------- component ---------- */

export function PQCMigrationProgress(): React.ReactElement {
  const { data, isLoading, error } = usePQCMigration();

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading PQC migration data...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load PQC migration data.
        </p>
      </div>
    );
  }

  const { overview, families, laggingProjects } = data;

  const donutData = [
    { name: 'Vulnerable', value: overview.vulnerable },
    { name: 'Safe', value: overview.safe },
    { name: 'Unknown', value: overview.unknown },
  ];

  return (
    <div>
      <div className="card-title" style={{ marginBottom: '16px' }}>
        PQC Migration Progress
      </div>

      {/* Overview: donut + stats */}
      <div className="g21" style={{ marginBottom: '24px' }}>
        <div className="card">
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {donutData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={DONUT_COLORS[entry.name] ?? '#6b7280'}
                    />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value: number, name: string) => [value, name]}
                  contentStyle={{
                    background: 'var(--bg-1)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    fontSize: '11px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginTop: '8px' }}>
            <LegendItem color="#ef4444" label="Vulnerable" value={`${String(overview.percentVulnerable)}%`} />
            <LegendItem color="#22c55e" label="Safe" value={`${String(overview.percentSafe)}%`} />
            <LegendItem color="#6b7280" label="Unknown" value={`${String(overview.percentUnknown)}%`} />
          </div>
        </div>

        <div className="card">
          <div className="card-title" style={{ marginBottom: '12px' }}>Overview</div>
          <div className="g2" style={{ gap: '10px' }}>
            <div className="stat">
              <div className="stat-label">Total Findings</div>
              <div className="stat-val" style={{ color: 'var(--accent)' }}>{overview.totalFindings}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Vulnerable</div>
              <div className="stat-val" style={{ color: 'var(--red)' }}>{overview.vulnerable}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Safe</div>
              <div className="stat-val" style={{ color: 'var(--green)' }}>{overview.safe}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Unknown</div>
              <div className="stat-val" style={{ color: 'var(--text-3)' }}>{overview.unknown}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Per-family progress bars */}
      <div className="card" style={{ marginBottom: '16px' }}>
        <div className="card-title" style={{ marginBottom: '12px' }}>Migration by Algorithm Family</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {families.map((fam: AlgorithmFamilyProgress) => (
            <FamilyBar key={fam.family} family={fam} />
          ))}
        </div>
      </div>

      {/* Lagging projects */}
      <div className="card">
        <div className="card-title" style={{ marginBottom: '12px' }}>Lagging Projects</div>
        {laggingProjects.length === 0 ? (
          <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
            All projects are on track with PQC migration.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Project</th>
                <th scope="col">Vulnerable</th>
                <th scope="col">Total</th>
                <th scope="col">% Vulnerable</th>
              </tr>
            </thead>
            <tbody>
              {laggingProjects.map((proj: LaggingProject) => (
                <tr key={proj.projectId}>
                  <td><strong>{proj.projectName}</strong></td>
                  <td style={{ color: 'var(--red)' }}>{proj.vulnerableCount}</td>
                  <td>{proj.totalCount}</td>
                  <td>
                    <span
                      style={{
                        color: proj.percentVulnerable > 50 ? 'var(--red)' : 'var(--orange)',
                        fontWeight: 600,
                      }}
                    >
                      {proj.percentVulnerable}%
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* ---------- sub-components ---------- */

function LegendItem({ color, label, value }: { color: string; label: string; value: string }): React.ReactElement {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
      <div
        style={{
          width: '10px',
          height: '10px',
          borderRadius: '2px',
          background: color,
        }}
      />
      <span style={{ color: 'var(--text-2)' }}>{label}</span>
      <span style={{ fontWeight: 600 }}>{value}</span>
    </div>
  );
}

function FamilyBar({ family }: { family: AlgorithmFamilyProgress }): React.ReactElement {
  const barColor = migrationBarColor(family.percentMigrated);
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
        <span style={{ fontWeight: 600 }}>{family.family}</span>
        <span style={{ color: 'var(--text-3)' }}>
          {family.safe}/{family.total} migrated ({family.percentMigrated}%)
        </span>
      </div>
      <div className="progress" style={{ width: '100%', height: '8px' }}>
        <div
          className="progress-fill"
          style={{
            width: `${String(family.percentMigrated)}%`,
            background: barColor,
            transition: 'width 0.3s',
          }}
        />
      </div>
      <div style={{ display: 'flex', gap: '12px', fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
        <span>Vulnerable: {family.vulnerable}</span>
        <span>Safe: {family.safe}</span>
        <span>Unknown: {family.unknown}</span>
      </div>
    </div>
  );
}
