import { useState, useMemo } from 'react';
import { useCBOMDiff, useScanSelectors } from '@/api/hooks/useCBOMDiff.ts';
import { cn } from '@/lib/utils.ts';
import type { DiffItem, DiffType, DiffSeverity } from '@/mocks/data/cbomDiff.ts';

/* ---------- helpers ---------- */

function diffTypeColor(type: DiffType): string {
  switch (type) {
    case 'added':
      return 'var(--green)';
    case 'removed':
      return 'var(--red)';
    case 'changed':
      return 'var(--yellow)';
    case 'unchanged':
      return 'var(--text-3)';
  }
}

function diffTypeLabel(type: DiffType): string {
  switch (type) {
    case 'added':
      return '+ Added';
    case 'removed':
      return '\u2212 Removed';
    case 'changed':
      return '~ Changed';
    case 'unchanged':
      return '= Unchanged';
  }
}

function diffRowClass(type: DiffType): string {
  switch (type) {
    case 'added':
      return 'diff-add';
    case 'removed':
      return 'diff-rm';
    case 'changed':
      return 'diff-ch';
    default:
      return '';
  }
}

function severityBadgeClass(severity: DiffSeverity): string {
  switch (severity) {
    case 'critical':
      return 'b-crit';
    case 'high':
      return 'b-high';
    case 'medium':
      return 'b-med';
    case 'low':
      return 'b-safe';
    case 'info':
      return 'b-safe';
  }
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

type FilterType = DiffType | 'all';
type SeverityFilter = DiffSeverity | 'all';

/* ---------- component ---------- */

export function CBOMDiff(): React.ReactElement {
  const { data: scans, isLoading: scansLoading } = useScanSelectors();
  const [baseScanId, setBaseScanId] = useState('scan-46');
  const [targetScanId, setTargetScanId] = useState('scan-47');
  const [typeFilter, setTypeFilter] = useState<FilterType>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [expandedItem, setExpandedItem] = useState<string | null>(null);

  const { data, isLoading, error } = useCBOMDiff(baseScanId, targetScanId);

  /* filtered items */
  const filteredItems = useMemo(() => {
    if (!data) return [];
    let items = data.items ?? [];
    if (typeFilter !== 'all') {
      items = items.filter((i) => i.diffType === typeFilter);
    }
    if (severityFilter !== 'all') {
      items = items.filter((i) => i.severity === severityFilter);
    }
    return items;
  }, [data, typeFilter, severityFilter]);

  if ((isLoading || scansLoading) && !data) {
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
          Failed to load CBOM diff data.
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
          CBOM Diff
        </h1>
        <div className="topbar-right">
          <button
            className="btn btn-outline"
            onClick={() => window.open('/api/v1/reports/diff?format=pdf', '_blank')}
          >
            Export Diff Report
          </button>
        </div>
      </div>

      {/* Scan selectors */}
      <div className="card" style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <div className="field-label">Base Scan (before)</div>
            <select
              className="filter"
              value={baseScanId}
              onChange={(e) => setBaseScanId(e.target.value)}
              aria-label="Select base scan"
            >
              {(scans ?? []).map((s) => (
                <option key={s.scanId} value={s.scanId}>
                  #{s.scanNumber} - {formatDate(s.date)} ({s.branch})
                </option>
              ))}
            </select>
          </div>
          <div style={{ fontSize: '20px', color: 'var(--text-4)', alignSelf: 'flex-end', paddingBottom: '4px' }}>
            &rarr;
          </div>
          <div>
            <div className="field-label">Target Scan (after)</div>
            <select
              className="filter"
              value={targetScanId}
              onChange={(e) => setTargetScanId(e.target.value)}
              aria-label="Select target scan"
            >
              {(scans ?? []).map((s) => (
                <option key={s.scanId} value={s.scanId}>
                  #{s.scanNumber} - {formatDate(s.date)} ({s.branch})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Summary bar */}
      <div className="g4">
        <div className="stat">
          <div className="stat-label">Added</div>
          <div className="stat-val" style={{ color: 'var(--green)' }}>+{data.summary?.added ?? 0}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Removed</div>
          <div className="stat-val" style={{ color: 'var(--red)' }}>-{data.summary?.removed ?? 0}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Changed</div>
          <div className="stat-val" style={{ color: 'var(--yellow)' }}>~{data.summary?.changed ?? 0}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Unchanged</div>
          <div className="stat-val" style={{ color: 'var(--text-3)' }}>={data.summary?.unchanged ?? 0}</div>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '12px', flexWrap: 'wrap' }}>
        {(['all', 'added', 'removed', 'changed'] as FilterType[]).map((t) => (
          <button
            key={t}
            className={cn('filter', typeFilter === t && 'active')}
            onClick={() => setTypeFilter(t)}
          >
            {t === 'all' ? `All (${String((data.items ?? []).length)})` : `${diffTypeLabel(t as DiffType)} (${String((data.items ?? []).filter((i) => i.diffType === t).length)})`}
          </button>
        ))}
        <div style={{ borderLeft: '1px solid var(--border)', margin: '0 4px' }} />
        <select
          className="filter"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
          aria-label="Filter by severity"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {/* Diff table */}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th scope="col">Type</th>
              <th scope="col">Severity</th>
              <th scope="col">Component</th>
              <th scope="col">File</th>
              <th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredItems.map((item) => (
              <DiffRow
                key={item.id}
                item={item}
                expanded={expandedItem === item.id}
                onToggle={() =>
                  setExpandedItem(expandedItem === item.id ? null : item.id)
                }
              />
            ))}
          </tbody>
        </table>
        {filteredItems.length === 0 && (
          <p style={{ color: 'var(--text-3)', fontSize: '12px', padding: '16px 0', textAlign: 'center' }}>
            No diff items match your filters.
          </p>
        )}
      </div>
    </div>
  );
}

/* ---------- diff row ---------- */

function DiffRow({
  item,
  expanded,
  onToggle,
}: {
  item: DiffItem;
  expanded: boolean;
  onToggle: () => void;
}): React.ReactElement {
  return (
    <>
      <tr className={cn(diffRowClass(item.diffType), 'clickable')} onClick={onToggle}>
        <td style={{ color: diffTypeColor(item.diffType), fontWeight: 600 }}>
          {diffTypeLabel(item.diffType)}
        </td>
        <td>
          <span className={cn('badge', severityBadgeClass(item.severity))}>
            {item.severity.toUpperCase()}
          </span>
        </td>
        <td>
          <strong>{item.component}</strong>
        </td>
        <td style={{ fontFamily: 'var(--font)', fontSize: '11px' }}>
          {item.file}:{item.line}
        </td>
        <td style={{ color: 'var(--text-2)', fontSize: '11px' }}>{item.details}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} style={{ padding: '12px 16px', background: 'var(--bg-0)' }}>
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              {item.oldValue && (
                <div style={{ flex: 1, minWidth: '200px' }}>
                  <div className="field-label" style={{ marginBottom: '4px' }}>Previous Value</div>
                  <div
                    className="code"
                    style={{
                      borderLeft: '3px solid var(--red)',
                      fontSize: '11px',
                      padding: '8px 10px',
                    }}
                  >
                    {item.oldValue}
                  </div>
                </div>
              )}
              {item.newValue && (
                <div style={{ flex: 1, minWidth: '200px' }}>
                  <div className="field-label" style={{ marginBottom: '4px' }}>New Value</div>
                  <div
                    className="code"
                    style={{
                      borderLeft: '3px solid var(--green)',
                      fontSize: '11px',
                      padding: '8px 10px',
                    }}
                  >
                    {item.newValue}
                  </div>
                </div>
              )}
            </div>
            <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-3)' }}>
              Type: {item.type} &middot; {item.details}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
