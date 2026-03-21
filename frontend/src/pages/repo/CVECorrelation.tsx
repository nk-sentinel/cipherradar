import { useState } from 'react';
import { useParams } from '@tanstack/react-router';
import { useCVECorrelation } from '@/api/hooks/useCVECorrelation.ts';
import { cn } from '@/lib/utils.ts';
import type { CVESeverity, CVEStatus } from '@/mocks/data/cveCorrelation.ts';

function severityBadgeClass(severity: CVESeverity): string {
  switch (severity) {
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

function statusBadgeClass(status: CVEStatus): string {
  return status === 'fixed' ? 'b-safe' : 'b-crit';
}

export function CVECorrelation(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const { data, isLoading, error } = useCVECorrelation(repoId);
  const [severityFilter, setSeverityFilter] = useState<CVESeverity | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<CVEStatus | 'all'>('all');
  const [libraryFilter, setLibraryFilter] = useState<string>('all');

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading CVE correlation data...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load CVE correlation data.
        </p>
      </div>
    );
  }

  // Get unique libraries for filter dropdown
  const uniqueLibraries = [...new Set(data.entries.map((e) => e.library))];

  // Apply filters
  let filtered = [...data.entries];
  if (severityFilter !== 'all') {
    filtered = filtered.filter((e) => e.cveSeverity === severityFilter);
  }
  if (statusFilter !== 'all') {
    filtered = filtered.filter((e) => e.cveStatus === statusFilter);
  }
  if (libraryFilter !== 'all') {
    filtered = filtered.filter((e) => e.library === libraryFilter);
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
          SBOM / CBOM CVE Correlation
        </h1>
      </div>

      {/* Stats */}
      <div className="g4" style={{ marginBottom: '16px' }}>
        <div className="stat" style={{ textAlign: 'center' }}>
          <div className="stat-val" style={{ color: 'var(--accent)' }}>{data.totalCves}</div>
          <div className="stat-label">Total CVEs</div>
        </div>
        <div className="stat" style={{ textAlign: 'center' }}>
          <div className="stat-val" style={{ color: 'var(--red)' }}>{data.criticalCount}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat" style={{ textAlign: 'center' }}>
          <div className="stat-val" style={{ color: 'var(--orange)' }}>{data.highCount}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat" style={{ textAlign: 'center' }}>
          <div className="stat-val" style={{ color: data.unfixedCount > 0 ? 'var(--red)' : 'var(--green)' }}>
            {data.unfixedCount}
          </div>
          <div className="stat-label">Unfixed</div>
        </div>
      </div>

      {/* Filters */}
      <div
        style={{
          display: 'flex',
          gap: '12px',
          marginBottom: '16px',
          alignItems: 'center',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-3)' }}>Severity:</span>
          <select
            className="input"
            style={{ width: '120px' }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as CVESeverity | 'all')}
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-3)' }}>Library:</span>
          <select
            className="input"
            style={{ width: '160px' }}
            value={libraryFilter}
            onChange={(e) => setLibraryFilter(e.target.value)}
          >
            <option value="all">All Libraries</option>
            {uniqueLibraries.map((lib) => (
              <option key={lib} value={lib}>
                {lib}
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-3)' }}>Status:</span>
          <select
            className="input"
            style={{ width: '120px' }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as CVEStatus | 'all')}
          >
            <option value="all">All</option>
            <option value="fixed">Fixed</option>
            <option value="unfixed">Unfixed</option>
          </select>
        </div>

        <div style={{ fontSize: '11px', color: 'var(--text-3)', marginLeft: 'auto' }}>
          Showing {filtered.length} of {data.totalCves} entries
        </div>
      </div>

      {/* CVE Correlation Table */}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Library</th>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>Crypto Finding</th>
              <th>Affected Versions</th>
              <th>Fix Version</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-3)' }}>
                  No CVE entries match the current filters.
                </td>
              </tr>
            ) : (
              filtered.map((entry) => (
                <tr key={entry.id}>
                  <td>
                    <div>
                      <strong>{entry.library}</strong>
                      <div style={{ fontSize: '10px', color: 'var(--text-3)' }}>
                        v{entry.libraryVersion}
                      </div>
                    </div>
                  </td>
                  <td>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${entry.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: 'var(--accent)', fontSize: '12px' }}
                    >
                      {entry.cveId}
                    </a>
                  </td>
                  <td>
                    <span className={cn('badge', severityBadgeClass(entry.cveSeverity))}>
                      {entry.cveSeverity.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontSize: '12px' }}>{entry.cryptoFindingTitle}</td>
                  <td style={{ fontSize: '11px', fontFamily: 'monospace' }}>{entry.affectedVersions}</td>
                  <td style={{ fontSize: '11px' }}>
                    {entry.fixedInVersion ? (
                      <span style={{ color: 'var(--green)' }}>v{entry.fixedInVersion}</span>
                    ) : (
                      <span style={{ color: 'var(--text-3)' }}>N/A</span>
                    )}
                  </td>
                  <td>
                    <span className={cn('badge', statusBadgeClass(entry.cveStatus))}>
                      {entry.cveStatus === 'fixed' ? 'Fixed' : 'Unfixed'}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
