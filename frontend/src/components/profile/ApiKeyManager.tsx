import { useState } from 'react';
import { useMyApiKeys, useRevokeApiKey } from '@/api/hooks/useApiKeys.ts';
import { ApiKeyCreateModal } from './ApiKeyCreateModal.tsx';

export function ApiKeyManager(): React.ReactElement {
  const { data: keys, isLoading, error } = useMyApiKeys();
  const revokeApiKey = useRevokeApiKey();
  const [showCreate, setShowCreate] = useState(false);

  if (showCreate) {
    return <ApiKeyCreateModal onClose={() => setShowCreate(false)} />;
  }

  return (
    <div className="card">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '12px',
        }}
      >
        <div className="card-title" style={{ marginBottom: 0 }}>
          My API Keys
        </div>
        <button
          className="btn btn-outline"
          onClick={() => setShowCreate(true)}
          data-testid="create-api-key-btn"
          style={{ fontSize: '11px' }}
        >
          + Create API Key
        </button>
      </div>

      {isLoading && (
        <p style={{ color: 'var(--text-2)', fontSize: '12px' }}>Loading API keys...</p>
      )}

      {error && (
        <p style={{ color: 'var(--red)', fontSize: '12px' }}>
          Failed to load API keys.
        </p>
      )}

      {keys && keys.length === 0 && (
        <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
          No API keys yet. Create one to authenticate CLI and CI/CD.
        </p>
      )}

      {keys && keys.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Key Prefix</th>
              <th>Scopes</th>
              <th>Created</th>
              <th>Last Used</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id} data-testid={`api-key-row-${key.id}`}>
                <td>
                  <strong>{key.name}</strong>
                </td>
                <td>
                  <code style={{ fontSize: '10px', fontFamily: 'var(--font-mono, monospace)', color: 'var(--text-2)' }}>
                    {key.prefix}...
                  </code>
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-2)' }}>
                  {key.scopes.join(', ')}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-3)' }}>
                  {key.createdAt}
                </td>
                <td style={{ fontSize: '11px', color: 'var(--text-3)' }}>
                  {key.lastUsed ?? 'Never'}
                </td>
                <td>
                  <span
                    style={{
                      padding: '2px 8px',
                      borderRadius: 'var(--radius)',
                      fontSize: '10px',
                      fontWeight: 600,
                      background: key.status === 'active' ? 'var(--badge-ok-bg)' : 'var(--badge-crit-bg)',
                      color: key.status === 'active' ? 'var(--badge-ok-fg)' : 'var(--badge-crit-fg)',
                      border: `1px solid ${key.status === 'active' ? 'var(--badge-ok-bd)' : 'var(--badge-crit-bd)'}`,
                    }}
                  >
                    {key.status}
                  </span>
                </td>
                <td>
                  {key.status === 'active' && (
                    <button
                      className="btn btn-outline"
                      style={{ fontSize: '10px', padding: '2px 8px', color: 'var(--red)' }}
                      data-testid={`revoke-key-${key.id}`}
                      disabled={revokeApiKey.isPending}
                      onClick={() => revokeApiKey.mutate(key.id)}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
