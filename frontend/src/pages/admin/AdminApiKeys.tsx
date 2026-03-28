import { useState, useMemo, useCallback } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useAuth } from '@/lib/auth.tsx';
import { useAdminApiKeys, useAdminRevokeApiKey, type AdminApiKey } from '@/api/hooks/useAdminApiKeys.ts';
import { AccessibleTable } from '@/components/ui/AccessibleTable.tsx';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function isStale(lastUsedAt: string | null, createdAt: string): boolean {
  const reference = lastUsedAt ?? createdAt;
  const d = new Date(reference);
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
  return diffDays >= 30;
}

function scopeLabel(scope: string): string {
  return scope.replace(/_/g, ' ').replace(/:/g, ':');
}

function exportCsv(keys: AdminApiKey[]): void {
  const header = 'Name,Owner,Scopes,Created,Last Used,Status';
  const rows = keys.map((k) =>
    [
      k.name,
      k.owner,
      k.scopes.join('; '),
      k.createdAt,
      k.lastUsedAt ?? 'Never',
      k.status,
    ]
      .map((v) => `"${v}"`)
      .join(','),
  );
  const csv = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `api-keys-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Page export
// ---------------------------------------------------------------------------

export function AdminApiKeys(): React.ReactElement {
  return (
    <RequireRole
      roles={['org-admin', 'security-manager']}
      fallback={
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
            Access denied. You do not have permission to view API keys. Contact your admin.
          </p>
        </div>
      }
    >
      <AdminApiKeysContent />
    </RequireRole>
  );
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

function AdminApiKeysContent(): React.ReactElement {
  const { user } = useAuth();
  const isOrgAdmin = user?.role === 'org-admin';

  const { data, isLoading, error } = useAdminApiKeys();
  const revokeKey = useAdminRevokeApiKey();

  // Filters
  const [ownerFilter, setOwnerFilter] = useState('');
  const [scopeFilter, setScopeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Derive unique owners and scopes from data
  const owners = useMemo(() => {
    if (!data?.items) return [];
    const set = new Set(data.items.map((k) => k.owner));
    return Array.from(set).sort();
  }, [data]);

  const allScopes = useMemo(() => {
    if (!data?.items) return [];
    const set = new Set(data.items.flatMap((k) => k.scopes));
    return Array.from(set).sort();
  }, [data]);

  const filtered = useMemo(() => {
    let items = data?.items ?? [];
    if (ownerFilter) items = items.filter((k) => k.owner === ownerFilter);
    if (scopeFilter) items = items.filter((k) => k.scopes.includes(scopeFilter));
    if (statusFilter) items = items.filter((k) => k.status === statusFilter);
    return items;
  }, [data, ownerFilter, scopeFilter, statusFilter]);

  const handleRevoke = useCallback(
    (keyId: string) => {
      if (window.confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
        revokeKey.mutate(keyId);
      }
    },
    [revokeKey],
  );

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
          Failed to load API keys.
        </p>
      </div>
    );
  }

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
          API Keys
        </h1>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ color: 'var(--text-3)', fontSize: '11px' }}>
            {filtered.length} key{filtered.length !== 1 ? 's' : ''}
          </span>
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '4px 10px' }}
            onClick={() => exportCsv(filtered)}
            data-testid="export-csv-btn"
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
        <select
          className="filter"
          value={ownerFilter}
          onChange={(e) => setOwnerFilter(e.target.value)}
          aria-label="Filter by owner"
          data-testid="owner-filter"
        >
          <option value="">All Owners</option>
          {owners.map((o) => (
            <option key={o} value={o}>{o}</option>
          ))}
        </select>

        <select
          className="filter"
          value={scopeFilter}
          onChange={(e) => setScopeFilter(e.target.value)}
          aria-label="Filter by scope"
          data-testid="scope-filter"
        >
          <option value="">All Scopes</option>
          {allScopes.map((s) => (
            <option key={s} value={s}>{scopeLabel(s)}</option>
          ))}
        </select>

        <select
          className="filter"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          aria-label="Filter by status"
          data-testid="status-filter"
        >
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="revoked">Revoked</option>
          <option value="expired">Expired</option>
        </select>
      </div>

      {/* Table */}
      <div className="card">
        <AccessibleTable
          columns={[
            { label: 'Name' },
            { label: 'Owner' },
            { label: 'Scopes' },
            { label: 'Created' },
            { label: 'Last Used' },
            { label: 'Status' },
            ...(isOrgAdmin ? [{ label: 'Actions' }] : []),
          ]}
          caption="Organization API keys"
          data-testid="admin-api-keys-table"
        >
          {filtered.length === 0 && (
            <tr>
              <td
                colSpan={isOrgAdmin ? 7 : 6}
                style={{ textAlign: 'center', color: 'var(--text-3)', fontSize: '12px', padding: '20px' }}
              >
                No API keys match the current filters.
              </td>
            </tr>
          )}
          {filtered.map((key) => {
            const stale = key.status === 'active' && isStale(key.lastUsedAt, key.createdAt);
            return (
              <tr key={key.id} data-testid={`api-key-row-${key.id}`}>
                <td style={{ fontWeight: 500, fontSize: '12px' }}>
                  {key.name}
                  <span style={{ color: 'var(--text-3)', fontSize: '10px', marginLeft: '6px' }}>
                    {key.keyPrefix}
                  </span>
                </td>
                <td style={{ fontSize: '11px' }}>{key.owner}</td>
                <td style={{ fontSize: '11px' }}>
                  {key.scopes.map((s) => (
                    <span
                      key={s}
                      className="badge"
                      style={{
                        fontSize: '9px',
                        padding: '1px 5px',
                        marginRight: '4px',
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      {scopeLabel(s)}
                    </span>
                  ))}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                  {formatDate(key.createdAt)}
                </td>
                <td style={{ fontSize: '11px', whiteSpace: 'nowrap' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    {stale && (
                      <span
                        title="Unused for 30+ days"
                        data-testid={`stale-indicator-${key.id}`}
                        style={{
                          display: 'inline-block',
                          width: '8px',
                          height: '8px',
                          borderRadius: '50%',
                          background: 'var(--orange)',
                        }}
                      />
                    )}
                    <span style={{ color: key.lastUsedAt ? 'var(--text-2)' : 'var(--text-3)' }}>
                      {key.lastUsedAt ? formatDate(key.lastUsedAt) : 'Never'}
                    </span>
                  </span>
                </td>
                <td>
                  <span
                    className={`badge ${
                      key.status === 'active'
                        ? 'b-green'
                        : key.status === 'revoked'
                          ? 'b-crit'
                          : 'b-yellow'
                    }`}
                    style={{ fontSize: '10px', padding: '1px 6px' }}
                  >
                    {key.status}
                  </span>
                </td>
                {isOrgAdmin && (
                  <td>
                    {key.status === 'active' && (
                      <button
                        className="btn btn-outline"
                        style={{ fontSize: '10px', padding: '2px 8px', color: 'var(--red)' }}
                        onClick={() => handleRevoke(key.id)}
                        disabled={revokeKey.isPending}
                        data-testid={`revoke-btn-${key.id}`}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                )}
              </tr>
            );
          })}
        </AccessibleTable>
      </div>

      {!isOrgAdmin && (
        <p style={{ marginTop: '12px', fontSize: '11px', color: 'var(--text-3)' }}>
          Read-only view. Contact an Org Admin to manage API keys.
        </p>
      )}
    </div>
  );
}
