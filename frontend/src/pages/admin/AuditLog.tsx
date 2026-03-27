import { useState, useCallback } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import {
  useAuditLogPaginated,
  useExportAuditLog,
  DATE_PRESETS,
  presetToDateRange,
  type DatePreset,
} from '@/api/hooks/useAuditLog.ts';
import type { AuditAction } from '@/mocks/data/admin.ts';
import { useToast } from '@/lib/use-toast.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ACTION_LABELS: Record<AuditAction, string> = {
  'user.login': 'User Login',
  'user.logout': 'User Logout',
  'user.invite': 'User Invited',
  'user.role_change': 'Role Changed',
  'scan.started': 'Scan Started',
  'scan.completed': 'Scan Completed',
  'policy.updated': 'Policy Updated',
  'settings.updated': 'Settings Updated',
  'integration.connected': 'Integration Connected',
  'integration.disconnected': 'Integration Disconnected',
  'finding.suppressed': 'Finding Suppressed',
  'cbom.exported': 'CBOM Exported',
};

const ACTION_TYPE_OPTIONS = [
  { value: '', label: 'All Actions' },
  { value: 'user', label: 'User / Auth' },
  { value: 'scan', label: 'Scans' },
  { value: 'policy', label: 'Policy' },
  { value: 'settings', label: 'Settings' },
  { value: 'integration', label: 'Integrations' },
  { value: 'finding', label: 'Findings' },
  { value: 'cbom', label: 'CBOM' },
];

const KNOWN_USERS = [
  { value: '', label: 'All Users' },
  { value: 'alex.chen@nk-sentinel.io', label: 'Alex Chen' },
  { value: 'sarah.kim@nk-sentinel.io', label: 'Sarah Kim' },
  { value: 'james.liu@nk-sentinel.io', label: 'James Liu' },
  { value: 'maria.garcia@nk-sentinel.io', label: 'Maria Garcia' },
];

const PAGE_SIZE = 25;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function actionCategory(action: AuditAction): string {
  if (action.startsWith('user.')) return 'auth';
  if (action.startsWith('scan.')) return 'scan';
  if (action.startsWith('policy.') || action.startsWith('settings.')) return 'config';
  if (action.startsWith('integration.')) return 'integration';
  if (action.startsWith('finding.') || action.startsWith('cbom.')) return 'data';
  return 'other';
}

function categoryColor(category: string): string {
  switch (category) {
    case 'auth':
      return 'var(--blue)';
    case 'scan':
      return 'var(--green)';
    case 'config':
      return 'var(--orange)';
    case 'integration':
      return 'var(--purple)';
    case 'data':
      return 'var(--yellow)';
    default:
      return 'var(--text-3)';
  }
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

// ---------------------------------------------------------------------------
// Page export
// ---------------------------------------------------------------------------

export function AuditLog(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin', 'security-manager']}>
      <AuditLogContent />
    </RequireRole>
  );
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

function AuditLogContent(): React.ReactElement {
  const { toast } = useToast();

  // Filters
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [projectFilter, setProjectFilter] = useState('');
  const [datePreset, setDatePreset] = useState<DatePreset>('30d');
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');
  const [page, setPage] = useState(1);

  // Compute date range
  const dateRange = datePreset === 'custom'
    ? (customFrom || customTo ? { from: customFrom, to: customTo } : null)
    : presetToDateRange(datePreset);

  const { data, isLoading, error } = useAuditLogPaginated({
    page,
    perPage: PAGE_SIZE,
    user: userFilter || undefined,
    action: actionFilter || undefined,
    project: projectFilter || undefined,
    dateFrom: dateRange?.from,
    dateTo: dateRange?.to,
  });

  const exportAudit = useExportAuditLog();

  const handleExport = useCallback(() => {
    exportAudit.mutate(
      {
        page: 1,
        perPage: 10000,
        user: userFilter || undefined,
        action: actionFilter || undefined,
        project: projectFilter || undefined,
        dateFrom: dateRange?.from,
        dateTo: dateRange?.to,
      },
      {
        onSuccess: (blob) => {
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          toast({ title: 'Audit log exported', variant: 'success' });
        },
        onError: () => {
          toast({ title: 'Failed to export audit log', variant: 'error' });
        },
      },
    );
  }, [exportAudit, userFilter, actionFilter, projectFilter, dateRange, toast]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  if (isLoading && !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load audit log.
        </p>
      </div>
    );
  }

  const entries = data?.items ?? [];

  return (
    <div>
      {/* Header */}
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
          Audit Log
        </h1>
        <div className="topbar-right" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ color: 'var(--text-3)', fontSize: '11px' }}>
            {data?.total ?? 0} entries
          </span>
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '4px 10px' }}
            disabled={exportAudit.isPending}
            onClick={handleExport}
            data-testid="export-csv-btn"
          >
            {exportAudit.isPending ? 'Exporting...' : 'Export CSV'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
        {/* Date preset */}
        <select
          className="filter"
          value={datePreset}
          onChange={(e) => { setDatePreset(e.target.value as DatePreset); setPage(1); }}
          aria-label="Date range preset"
          data-testid="date-preset"
        >
          {DATE_PRESETS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>

        {/* Custom date inputs */}
        {datePreset === 'custom' && (
          <>
            <input
              className="input"
              type="date"
              value={customFrom}
              onChange={(e) => { setCustomFrom(e.target.value); setPage(1); }}
              aria-label="Date from"
              data-testid="custom-date-from"
              style={{ width: '140px', fontSize: '11px' }}
            />
            <input
              className="input"
              type="date"
              value={customTo}
              onChange={(e) => { setCustomTo(e.target.value); setPage(1); }}
              aria-label="Date to"
              data-testid="custom-date-to"
              style={{ width: '140px', fontSize: '11px' }}
            />
          </>
        )}

        {/* User dropdown */}
        <select
          className="filter"
          value={userFilter}
          onChange={(e) => { setUserFilter(e.target.value); setPage(1); }}
          aria-label="Filter by user"
          data-testid="user-filter"
        >
          {KNOWN_USERS.map((u) => (
            <option key={u.value} value={u.value}>
              {u.label}
            </option>
          ))}
        </select>

        {/* Action type dropdown */}
        <select
          className="filter"
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          aria-label="Filter by action type"
          data-testid="action-filter"
        >
          {ACTION_TYPE_OPTIONS.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>

        {/* Project filter */}
        <input
          className="input"
          type="text"
          placeholder="Filter by project..."
          value={projectFilter}
          onChange={(e) => { setProjectFilter(e.target.value); setPage(1); }}
          aria-label="Filter by project"
          data-testid="project-filter"
          style={{ width: '160px', fontSize: '11px' }}
        />
      </div>

      {/* Audit log table */}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-3)', fontSize: '12px', padding: '20px' }}>
                  No entries match the current filters.
                </td>
              </tr>
            )}
            {entries.map((entry) => {
              const cat = actionCategory(entry.action);
              return (
                <tr key={entry.id} data-testid={`audit-row-${entry.id}`}>
                  <td style={{ fontSize: '11px', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                    {formatTimestamp(entry.timestamp)}
                  </td>
                  <td style={{ fontSize: '11px' }}>{entry.user}</td>
                  <td>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: 'var(--radius)',
                        fontSize: '10px',
                        fontWeight: 600,
                        background: `color-mix(in srgb, ${categoryColor(cat)} 15%, transparent)`,
                        color: categoryColor(cat),
                        border: `1px solid color-mix(in srgb, ${categoryColor(cat)} 30%, transparent)`,
                      }}
                    >
                      {ACTION_LABELS[entry.action]}
                    </span>
                  </td>
                  <td style={{ fontWeight: 500, fontSize: '12px' }}>{entry.resource}</td>
                  <td style={{ color: 'var(--text-3)', fontSize: '11px' }}>
                    {entry.detail ?? '\u2014'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: '8px',
            marginTop: '16px',
          }}
          data-testid="audit-pagination"
        >
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '4px 10px' }}
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </button>
          <span style={{ fontSize: '12px', color: 'var(--text-2)' }}>
            Page {page} of {totalPages}
          </span>
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '4px 10px' }}
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
