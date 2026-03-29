import { useState } from 'react';
import { useCertificateTracker } from '@/api/hooks/useCertificateTracker.ts';
import type { CertificateEntry } from '@/api/hooks/useCertificateTracker.ts';
import { cn } from '@/lib/utils.ts';

/* ---------- helpers ---------- */

function statusBadgeClass(color: string): string {
  switch (color) {
    case 'green':
      return 'b-safe';
    case 'amber':
      return 'b-med';
    case 'red':
      return 'b-high';
    case 'black':
      return 'b-crit';
    default:
      return 'b-safe';
  }
}

function statusLabel(color: string, days: number): string {
  switch (color) {
    case 'black':
      return 'Expired';
    case 'red':
      return `${String(days)}d remaining`;
    case 'amber':
      return `${String(days)}d remaining`;
    case 'green':
      return `${String(days)}d remaining`;
    default:
      return 'Unknown';
  }
}

function statusDotStyle(color: string): React.CSSProperties {
  const colorMap: Record<string, string> = {
    green: 'var(--green)',
    amber: 'var(--orange)',
    red: 'var(--red)',
    black: 'var(--text-1)',
  };
  return {
    display: 'inline-block',
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: colorMap[color] ?? 'var(--text-3)',
    marginRight: '6px',
  };
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

/* ---------- component ---------- */

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'black', label: 'Expired' },
  { value: 'red', label: 'Critical (<30d)' },
  { value: 'amber', label: 'Warning (30-90d)' },
  { value: 'green', label: 'Safe (>90d)' },
];

const PAGE_SIZE = 25;

export function CertificateTracker(): React.ReactElement {
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [page, setPage] = useState(1);

  const { data, isLoading, error } = useCertificateTracker({
    statusColor: statusFilter || null,
    page,
    perPage: PAGE_SIZE,
  });

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
          Failed to load certificate tracker data.
        </p>
      </div>
    );
  }

  const totalPages = Math.ceil(data.total / PAGE_SIZE);

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
          Certificate Tracker
        </h1>
        <div className="topbar-right" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <select
            data-testid="cert-status-filter"
            className="btn btn-outline"
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            style={{
              background: 'var(--bg-1)',
              border: '1px solid var(--border)',
              color: 'var(--text-1)',
              padding: '6px 10px',
              borderRadius: 'var(--radius)',
              fontSize: '12px',
            }}
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Summary stats */}
      <div className="g4">
        <div className="stat">
          <div className="stat-label">Total</div>
          <div className="stat-val" style={{ color: 'var(--accent)' }}>
            {data.total}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Expired</div>
          <div className="stat-val" style={{ color: 'var(--red)' }}>
            {(data.items ?? []).filter((c) => c.statusColor === 'black').length}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Critical</div>
          <div className="stat-val" style={{ color: 'var(--orange)' }}>
            {(data.items ?? []).filter((c) => c.statusColor === 'red').length}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Safe</div>
          <div className="stat-val" style={{ color: 'var(--green)' }}>
            {(data.items ?? []).filter((c) => c.statusColor === 'green').length}
          </div>
        </div>
      </div>

      {/* Certificate table */}
      <div className="card">
        <div className="card-title">Certificates ({data.total})</div>
        {(data.items ?? []).length === 0 ? (
          <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
            {data.total === 0 && !statusFilter
              ? 'No certificates found. Certificate data will appear here once scans detect X.509 certificates, TLS endpoints, or PEM files in your codebase.'
              : 'No certificates match the selected filter.'}
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Subject</th>
                <th scope="col">Issuer</th>
                <th scope="col">Expires</th>
                <th scope="col">Days Remaining</th>
                <th scope="col">Status</th>
                <th scope="col">Project</th>
                <th scope="col">File</th>
              </tr>
            </thead>
            <tbody>
              {(data.items ?? []).map((cert: CertificateEntry) => (
                <tr key={cert.id}>
                  <td>
                    <strong>{cert.subject}</strong>
                  </td>
                  <td>{cert.issuer}</td>
                  <td>{formatDate(cert.notAfter)}</td>
                  <td>
                    <span style={statusDotStyle(cert.statusColor)} />
                    {cert.daysRemaining < 0
                      ? `${String(Math.abs(cert.daysRemaining))}d ago`
                      : `${String(cert.daysRemaining)}d`}
                  </td>
                  <td>
                    <span
                      className={cn('badge', statusBadgeClass(cert.statusColor))}
                      data-testid="cert-status-badge"
                    >
                      {statusLabel(cert.statusColor, cert.daysRemaining)}
                    </span>
                  </td>
                  <td>{cert.projectName}</td>
                  <td style={{ fontSize: '11px', color: 'var(--text-3)' }}>{cert.filePath}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginTop: '12px',
              fontSize: '12px',
            }}
          >
            <span style={{ color: 'var(--text-3)' }}>
              Page {page} of {totalPages} ({data.total} total)
            </span>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                className="btn btn-outline"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                style={{ padding: '4px 10px', fontSize: '11px' }}
              >
                Previous
              </button>
              <button
                className="btn btn-outline"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                style={{ padding: '4px 10px', fontSize: '11px' }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
