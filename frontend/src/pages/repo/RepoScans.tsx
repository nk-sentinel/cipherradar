import { useScan } from '@/api/hooks/useScans.ts';
import { SeverityChart } from '@/components/charts/SeverityChart.tsx';
import { AlgorithmChart } from '@/components/charts/AlgorithmChart.tsx';
import { SeverityBadge } from '@/components/findings/SeverityBadge.tsx';
import { QuantumBadge } from '@/components/findings/QuantumBadge.tsx';
import type { Severity, QuantumStatus } from '@/mocks/data/findings.ts';

/** Map scan finding quantum values to QuantumStatus type used by QuantumBadge */
function toQuantumStatus(quantum: string | null): QuantumStatus {
  if (quantum === 'vulnerable' || quantum === 'broken' || quantum === 'safe') {
    return quantum;
  }
  return 'unknown';
}

interface RepoScansProps {
  scanId: string;
}

export function RepoScans({ scanId }: RepoScansProps): React.ReactElement {
  const { data: scan, isLoading, error } = useScan(scanId);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading scan details...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          {error ? 'Failed to load scan details.' : 'Scan not found.'}
        </p>
      </div>
    );
  }

  return (
    <div>
      {/* Header with export buttons */}
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
          Scan #{scan.number} — {scan.branch} ({scan.commit})
        </h1>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-outline" onClick={() => window.open('/api/v1/cbom/' + scanId + '/export?format=cyclonedx', '_blank')}>
            CBOM
          </button>
          <button className="btn btn-outline" onClick={() => window.open('/api/v1/cbom/' + scanId + '/export?format=sarif', '_blank')}>
            SARIF
          </button>
          <button className="btn btn-outline" onClick={() => window.open('/api/v1/cbom/' + scanId + '/export?format=pdf', '_blank')}>
            PDF
          </button>
        </div>
      </div>

      {/* Severity stat cards */}
      <div
        data-testid="severity-stats"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '12px',
          marginBottom: '16px',
        }}
      >
        <div className="stat">
          <div className="stat-label">Critical</div>
          <div className="stat-val" style={{ color: 'var(--red)' }} data-testid="stat-critical">
            {scan.critical}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">High</div>
          <div className="stat-val" style={{ color: 'var(--orange)' }} data-testid="stat-high">
            {scan.high}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Medium</div>
          <div className="stat-val" style={{ color: 'var(--yellow)' }} data-testid="stat-medium">
            {scan.medium}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Low + Info</div>
          <div className="stat-val" style={{ color: 'var(--text-3)' }} data-testid="stat-low-info">
            {(scan.low ?? 0) + (scan.info ?? 0)}
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
        <SeverityChart
          data={{
            critical: scan.critical,
            high: scan.high,
            medium: scan.medium,
            low: scan.low,
            info: scan.info,
          }}
        />
        <AlgorithmChart data={scan.algorithms ?? []} />
      </div>

      {/* Top findings table */}
      <div className="card">
        <div className="card-title">Top Findings</div>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>File</th>
              <th>Line</th>
              <th>Finding</th>
              <th>Quantum</th>
            </tr>
          </thead>
          <tbody>
            {(scan.findings ?? []).map((f) => (
                <tr key={f.id}>
                  <td>
                    <SeverityBadge severity={f.severity as Severity} />
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>{f.file}</td>
                  <td>{f.line}</td>
                  <td>{f.finding}</td>
                  <td>
                    <QuantumBadge status={toQuantumStatus(f.quantum)} />
                  </td>
                </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
