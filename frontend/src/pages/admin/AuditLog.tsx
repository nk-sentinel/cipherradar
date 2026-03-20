import { useState } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useAuditLog } from '@/api/hooks/useAdmin.ts';
import type { AuditAction } from '@/mocks/data/admin.ts';

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

const ALL_CATEGORIES = [
  { value: '', label: 'All Actions' },
  { value: 'auth', label: 'Authentication' },
  { value: 'scan', label: 'Scans' },
  { value: 'config', label: 'Configuration' },
  { value: 'integration', label: 'Integrations' },
  { value: 'data', label: 'Data / Export' },
];

export function AuditLog(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin', 'security-manager']}>
      <AuditLogContent />
    </RequireRole>
  );
}

function AuditLogContent(): React.ReactElement {
  const { data, isLoading, error } = useAuditLog();
  const [categoryFilter, setCategoryFilter] = useState('');

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
          Failed to load audit log.
        </p>
      </div>
    );
  }

  const filtered = categoryFilter
    ? data.filter((entry) => actionCategory(entry.action) === categoryFilter)
    : data;

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
          Audit Log
        </h1>
        <div className="topbar-right">
          <span style={{ color: 'var(--text-3)', fontSize: '11px' }}>
            {filtered.length} entries
          </span>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <select
          className="filter"
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          aria-label="Filter by action category"
        >
          {ALL_CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
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
            {filtered.map((entry) => {
              const cat = actionCategory(entry.action);
              return (
                <tr key={entry.id}>
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
    </div>
  );
}
