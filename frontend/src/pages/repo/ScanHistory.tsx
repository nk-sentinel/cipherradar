import { useNavigate } from '@tanstack/react-router';
import { useScans } from '@/api/hooks/useScans.ts';
import { cn } from '@/lib/utils.ts';

function severityBadgeClass(count: number): string {
  if (count > 4) return 'badge b-crit';
  if (count > 0) return 'badge b-high';
  return 'badge b-safe';
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

interface ScanHistoryProps {
  repoId: string;
}

export function ScanHistory({ repoId }: ScanHistoryProps): React.ReactElement {
  const { data: scans, isLoading, error } = useScans(repoId);
  const navigate = useNavigate();

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading scans...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>Failed to load scans.</p>
      </div>
    );
  }

  if (!scans || scans.length === 0) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>No scans found for this repository.</p>
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
          Scan History
        </h1>
      </div>

      <div className="card">
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
            {scans.map((scan) => (
              <tr
                key={scan.id}
                className={cn('clickable')}
                style={{ cursor: 'pointer' }}
                onClick={() => void navigate({ to: '/repos/$repoId/scans/$scanId', params: { repoId, scanId: scan.id } })}
              >
                <td>#{scan.number}</td>
                <td>{scan.branch}</td>
                <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>{scan.commit}</td>
                <td>{scan.totalFindings}</td>
                <td>
                  <span className={severityBadgeClass(scan.critical)}>{scan.critical}</span>
                </td>
                <td>{scan.duration}</td>
                <td style={{ color: 'var(--text-3)' }}>{formatRelativeTime(scan.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
