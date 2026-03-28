import { useState, type FormEvent } from 'react';
import { useCreateApiKey } from '@/api/hooks/useApiKeys.ts';
import { useAuth } from '@/lib/auth.tsx';
import type { Role } from '@/lib/roles.ts';

interface ApiKeyCreateModalProps {
  onClose: () => void;
}

const EXPIRY_OPTIONS: { label: string; value: number | null }[] = [
  { label: '30 days', value: 30 },
  { label: '60 days', value: 60 },
  { label: '90 days', value: 90 },
  { label: '180 days', value: 180 },
  { label: '365 days', value: 365 },
  { label: 'Never', value: null },
];

/**
 * Available scopes, capped by user role per D10.
 */
const ALL_SCOPES = [
  'scan:read',
  'scan:write',
  'cbom:read',
  'cbom:write',
  'project:read',
  'project:write',
];

const SCOPE_BY_ROLE: Record<Role, string[]> = {
  'org-admin': ALL_SCOPES,
  'security-manager': ALL_SCOPES,
  'security-engineer': ['scan:read', 'scan:write', 'cbom:read', 'cbom:write', 'project:read'],
  'team-manager': ['scan:read', 'scan:write', 'cbom:read', 'project:read'],
  'compliance-auditor': ['scan:read', 'cbom:read', 'project:read'],
  developer: ['scan:read', 'scan:write', 'cbom:read', 'project:read'],
  guest: ['scan:read', 'cbom:read'],
};

export function ApiKeyCreateModal({ onClose }: ApiKeyCreateModalProps): React.ReactElement {
  const { user } = useAuth();
  const createApiKey = useCreateApiKey();
  const [name, setName] = useState('');
  const [expiresInDays, setExpiresInDays] = useState<number | null>(90);
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [rawKey, setRawKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (user?.role === 'guest') {
    return (
      <div className="card" data-testid="api-key-guest-denied">
        <div className="card-title">Create API Key</div>
        <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
          Guests cannot create API keys. Contact your administrator to upgrade your role.
        </p>
        <button className="btn btn-outline" onClick={onClose}>Close</button>
      </div>
    );
  }

  const availableScopes = user ? SCOPE_BY_ROLE[user.role] ?? [] : [];

  const toggleScope = (scope: string): void => {
    setSelectedScopes((prev) =>
      prev.includes(scope)
        ? prev.filter((s) => s !== scope)
        : [...prev, scope],
    );
  };

  const handleSubmit = (e: FormEvent): void => {
    e.preventDefault();
    createApiKey.mutate(
      { name, expiresInDays, scopes: selectedScopes },
      {
        onSuccess: (data) => {
          setRawKey(data.rawKey);
        },
      },
    );
  };

  const handleCopy = (): void => {
    if (rawKey) {
      void navigator.clipboard.writeText(rawKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Success state — show raw key once
  if (rawKey) {
    return (
      <div className="card" data-testid="api-key-success">
        <div className="card-title">API Key Created</div>
        <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
          Copy this key now. You will not be able to see it again.
        </p>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 12px',
            background: 'var(--surface-2)',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--border)',
            marginBottom: '12px',
          }}
        >
          <code
            data-testid="raw-key-display"
            style={{
              flex: 1,
              fontSize: '11px',
              fontFamily: 'var(--font-mono, monospace)',
              wordBreak: 'break-all',
              color: 'var(--green)',
            }}
          >
            {rawKey}
          </code>
          <button
            className="btn btn-outline"
            onClick={handleCopy}
            data-testid="copy-key-btn"
            style={{ flexShrink: 0, fontSize: '11px' }}
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
        <button className="btn btn-accent" onClick={onClose}>
          Done
        </button>
      </div>
    );
  }

  return (
    <div className="card" data-testid="api-key-create-modal">
      <div className="card-title">Create API Key</div>
      <form onSubmit={handleSubmit}>
        <div className="g2" style={{ marginBottom: '8px' }}>
          <div className="field">
            <label className="field-label" htmlFor="api-key-name">
              Name
            </label>
            <input
              id="api-key-name"
              className="input"
              type="text"
              placeholder="e.g. CI/CD pipeline"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="api-key-expiry">
              Expires
            </label>
            <select
              id="api-key-expiry"
              className="input"
              value={expiresInDays === null ? 'never' : String(expiresInDays)}
              onChange={(e) =>
                setExpiresInDays(e.target.value === 'never' ? null : Number(e.target.value))
              }
            >
              {EXPIRY_OPTIONS.map((opt) => (
                <option key={opt.label} value={opt.value === null ? 'never' : String(opt.value)}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="field" style={{ marginBottom: '12px' }}>
          <label className="field-label">Scopes</label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {availableScopes.map((scope) => (
              <label
                key={scope}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  fontSize: '11px',
                  color: 'var(--text-2)',
                  cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={selectedScopes.includes(scope)}
                  onChange={() => toggleScope(scope)}
                />
                {scope}
              </label>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="submit"
            className="btn btn-accent"
            disabled={createApiKey.isPending || !name.trim() || selectedScopes.length === 0}
          >
            {createApiKey.isPending ? 'Creating...' : 'Create Key'}
          </button>
          <button type="button" className="btn btn-outline" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
