import { useState, useCallback } from 'react';
import { useAssets } from '@/api/hooks/useAssets.ts';
import { cn } from '@/lib/utils.ts';
import type { AssetFilters, AssetType, QuantumAssetStatus, ComplianceTag } from '@/mocks/data/assets.ts';

const ASSET_TYPES: { value: AssetType | ''; label: string }[] = [
  { value: '', label: 'All Types' },
  { value: 'algorithm', label: 'Algorithm' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'key', label: 'Key' },
  { value: 'certificate', label: 'Certificate' },
];

const LANGUAGES = [
  '', 'Java', 'Python', 'JavaScript', 'TypeScript', 'Go', 'Kotlin',
];

const QUANTUM_STATUSES: { value: QuantumAssetStatus | ''; label: string }[] = [
  { value: '', label: 'All Status' },
  { value: 'safe', label: 'Safe' },
  { value: 'vulnerable', label: 'Vulnerable' },
  { value: 'broken', label: 'Broken' },
  { value: 'unknown', label: 'Unknown' },
];

const COMPLIANCE_FRAMEWORKS: { value: ComplianceTag | ''; label: string }[] = [
  { value: '', label: 'All Frameworks' },
  { value: 'NIST 800-131A', label: 'NIST 800-131A' },
  { value: 'FIPS 140-3', label: 'FIPS 140-3' },
  { value: 'CNSA 2.0', label: 'CNSA 2.0' },
];

function quantumBadgeClass(status: QuantumAssetStatus): string {
  switch (status) {
    case 'safe':
      return 'b-safe';
    case 'vulnerable':
      return 'b-vuln';
    case 'broken':
      return 'b-broken';
    case 'unknown':
      return 'b-med';
  }
}

function quantumLabel(status: QuantumAssetStatus): string {
  switch (status) {
    case 'safe':
      return 'Safe';
    case 'vulnerable':
      return 'Vuln';
    case 'broken':
      return 'Broken';
    case 'unknown':
      return 'Unknown';
  }
}

function typeBadgeClass(type: AssetType): string {
  switch (type) {
    case 'algorithm':
      return 'b-high';
    case 'protocol':
      return 'b-med';
    case 'key':
      return 'b-crit';
    case 'certificate':
      return 'b-safe';
  }
}

const PAGE_SIZE = 15;

export function AssetExplorer(): React.ReactElement {
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState<AssetFilters>({});
  const [page, setPage] = useState(1);

  const appliedFilters: AssetFilters = {
    ...filters,
    search: search || undefined,
  };

  const { data, isLoading, error } = useAssets(appliedFilters, page, PAGE_SIZE);

  const updateFilter = useCallback(<K extends keyof AssetFilters>(key: K, value: AssetFilters[K]) => {
    setFilters((prev) => {
      const next = { ...prev };
      if (value === '' || value === undefined) {
        delete next[key];
      } else {
        next[key] = value;
      }
      return next;
    });
    setPage(1);
  }, []);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  const exportCSV = useCallback(() => {
    if (!data) return;
    const header = 'Name,Type,Language,Repository,File,Line,Quantum Status,Compliance\n';
    const rows = (data.assets ?? []).map((a) =>
      [
        a.name,
        a.type,
        a.language,
        a.repository,
        a.file,
        String(a.line),
        a.quantumStatus,
        (a.compliance ?? []).join('; '),
      ]
        .map((v) => `"${v}"`)
        .join(','),
    );
    const csv = header + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'crypto-assets.csv';
    a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  if (error) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load asset data.
        </p>
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
          Findings
        </h1>
        <div className="topbar-right">
          <button className="btn btn-outline" onClick={exportCSV}>
            Export CSV
          </button>
        </div>
      </div>

      {/* Search + Filters */}
      <div
        style={{
          display: 'flex',
          gap: '8px',
          marginBottom: '16px',
          flexWrap: 'wrap',
          alignItems: 'center',
        }}
      >
        <input
          className="input"
          style={{ width: '260px', flexShrink: 0 }}
          placeholder="Search assets..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
        <select
          className="filter"
          value={filters.type ?? ''}
          onChange={(e) => updateFilter('type', (e.target.value || undefined) as AssetType | undefined)}
          aria-label="Filter by type"
        >
          {ASSET_TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        <select
          className="filter"
          value={filters.language ?? ''}
          onChange={(e) => updateFilter('language', e.target.value || undefined)}
          aria-label="Filter by language"
        >
          {LANGUAGES.map((l) => (
            <option key={l} value={l}>{l || 'All Languages'}</option>
          ))}
        </select>
        <select
          className="filter"
          value={filters.quantumStatus ?? ''}
          onChange={(e) => updateFilter('quantumStatus', (e.target.value || undefined) as QuantumAssetStatus | undefined)}
          aria-label="Filter by quantum status"
        >
          {QUANTUM_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        <select
          className="filter"
          value={filters.compliance ?? ''}
          onChange={(e) => updateFilter('compliance', (e.target.value || undefined) as ComplianceTag | undefined)}
          aria-label="Filter by compliance"
        >
          {COMPLIANCE_FRAMEWORKS.map((f) => (
            <option key={f.value} value={f.value}>{f.label}</option>
          ))}
        </select>
      </div>

      {/* Results count */}
      {data && (
        <div style={{ fontSize: '11px', color: 'var(--text-3)', marginBottom: '8px' }}>
          {data.total} asset{data.total !== 1 ? 's' : ''} found
        </div>
      )}

      {/* Assets table */}
      <div className="card">
        {isLoading ? (
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
        ) : data && (data.assets ?? []).length === 0 ? (
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>No assets match your filters.</p>
        ) : data ? (
          <table>
            <thead>
              <tr>
                <th scope="col">Asset Name</th>
                <th scope="col">Type</th>
                <th scope="col">Language</th>
                <th scope="col">Repository</th>
                <th scope="col">File:Line</th>
                <th scope="col">Quantum Status</th>
                <th scope="col">Compliance</th>
              </tr>
            </thead>
            <tbody>
              {(data.assets ?? []).map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <strong>{asset.name}</strong>
                  </td>
                  <td>
                    <span className={cn('badge', typeBadgeClass(asset.type))}>
                      {asset.type}
                    </span>
                  </td>
                  <td>{asset.language}</td>
                  <td>{asset.repository}</td>
                  <td style={{ fontFamily: 'var(--font)', fontSize: '11px' }}>
                    {asset.file}:{asset.line}
                  </td>
                  <td>
                    <span className={cn('badge', quantumBadgeClass(asset.quantumStatus))}>
                      {quantumLabel(asset.quantumStatus)}
                    </span>
                  </td>
                  <td>
                    {(asset.compliance ?? []).length === 0 ? (
                      <span style={{ color: 'var(--text-4)', fontSize: '11px' }}>None</span>
                    ) : (
                      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {(asset.compliance ?? []).map((c) => (
                          <span
                            key={c}
                            style={{
                              fontSize: '9px',
                              padding: '1px 5px',
                              borderRadius: 'var(--radius)',
                              border: '1px solid var(--border)',
                              color: 'var(--text-2)',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>

      {/* Pagination */}
      {data && totalPages > 1 && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: '6px',
            marginTop: '16px',
          }}
        >
          <button
            className="btn btn-outline"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            style={{ padding: '5px 10px', fontSize: '11px' }}
          >
            Prev
          </button>
          {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
            <button
              key={p}
              className={cn('btn', p === page ? 'btn-accent' : 'btn-outline')}
              onClick={() => setPage(p)}
              style={{ padding: '5px 10px', fontSize: '11px', minWidth: '32px' }}
            >
              {p}
            </button>
          ))}
          <button
            className="btn btn-outline"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            style={{ padding: '5px 10px', fontSize: '11px' }}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
