import { useParams } from '@tanstack/react-router';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
} from 'recharts';
import { useRuntimeSummary } from '@/api/hooks/useRuntime.ts';
import type { RuntimeSummary } from '@/mocks/data/runtime.ts';
import { cn } from '@/lib/utils.ts';

export function RuntimeView(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const { data: rawData, isLoading, error } = useRuntimeSummary(repoId);
  const data = rawData as RuntimeSummary | undefined;

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading runtime data...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load runtime enrichment data.
        </p>
      </div>
    );
  }

  const observations = data.observations ?? [];
  const mismatchCount = observations.filter((o) => o.mismatch).length;

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
          Runtime Enrichment
        </h1>
      </div>

      {/* Stats */}
      <div className="g3">
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '48px', color: 'var(--accent)' }}>
            {observations.length}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            Services Observed
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '48px', color: mismatchCount > 0 ? 'var(--red)' : 'var(--green)' }}>
            {mismatchCount}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            TLS Mismatches
          </div>
        </div>
        <div className="stat" style={{ textAlign: 'center', padding: '20px' }}>
          <div className="stat-val" style={{ fontSize: '48px', color: 'var(--green)' }}>
            {observations.length - mismatchCount}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            Matching Config
          </div>
        </div>
      </div>

      <div className="g2">
        {/* Configured vs Observed TLS Versions Chart */}
        <div className="card">
          <div className="card-title">Configured vs Observed TLS Versions</div>
          <div style={{ height: '220px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.tlsVersionChart ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis
                  dataKey="version"
                  tick={{ fontSize: 10, fill: 'var(--text-3)' }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis tick={{ fontSize: 10, fill: 'var(--text-3)' }} />
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-2)',
                    border: '1px solid var(--border)',
                    fontSize: '11px',
                    color: 'var(--text-1)',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '10px' }} />
                <Bar
                  dataKey="configured"
                  name="Configured (CBOM)"
                  fill="var(--blue)"
                  radius={[3, 3, 0, 0]}
                  isAnimationActive={false}
                />
                <Bar
                  dataKey="observed"
                  name="Observed (Runtime)"
                  fill="var(--orange)"
                  radius={[3, 3, 0, 0]}
                  isAnimationActive={false}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Mismatch summary */}
        <div className="card">
          <div className="card-title">Mismatch Summary</div>
          {mismatchCount === 0 ? (
            <div style={{ padding: '20px', textAlign: 'center' }}>
              <div style={{ fontSize: '14px', color: 'var(--green)', fontWeight: 600 }}>
                All Clear
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
                All observed TLS versions match their configured values.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {observations
                .filter((o) => o.mismatch)
                .map((o) => (
                  <div
                    key={o.id}
                    className="alert alert-error"
                    style={{ margin: 0 }}
                  >
                    <strong>{o.serviceName}:</strong> configured {o.configuredTlsVersion} but observed{' '}
                    <span style={{ color: 'var(--red)', fontWeight: 600 }}>{o.observedTlsVersion}</span>
                  </div>
                ))}
            </div>
          )}
        </div>
      </div>

      {/* Observations table */}
      <div className="card" style={{ marginTop: '16px' }}>
        <div className="card-title">Runtime Observations</div>
        <table>
          <thead>
            <tr>
              <th>Service</th>
              <th>Observed TLS</th>
              <th>Configured TLS</th>
              <th>Cipher Suite</th>
              <th>Timestamp</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {observations.map((obs) => (
              <tr
                key={obs.id}
                style={obs.mismatch ? { background: 'rgba(239, 68, 68, 0.06)' } : undefined}
              >
                <td><strong>{obs.serviceName}</strong></td>
                <td
                  style={{
                    color: obs.mismatch ? 'var(--red)' : 'var(--text-1)',
                    fontWeight: obs.mismatch ? 600 : 400,
                  }}
                >
                  {obs.observedTlsVersion}
                </td>
                <td>{obs.configuredTlsVersion}</td>
                <td style={{ fontSize: '11px', fontFamily: 'monospace' }}>{obs.observedCipherSuite}</td>
                <td style={{ fontSize: '11px' }}>
                  {new Date(obs.timestamp).toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </td>
                <td>
                  <span className={cn('badge', obs.mismatch ? 'b-crit' : 'b-safe')}>
                    {obs.mismatch ? 'Mismatch' : 'OK'}
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
