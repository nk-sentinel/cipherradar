import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useIntegrations } from '@/api/hooks/useAdmin.ts';
import type { IntegrationStatus } from '@/mocks/data/admin.ts';

function statusColor(status: IntegrationStatus): string {
  switch (status) {
    case 'connected':
      return 'var(--green)';
    case 'disconnected':
      return 'var(--text-4)';
    case 'error':
      return 'var(--red)';
  }
}

function statusLabel(status: IntegrationStatus): string {
  switch (status) {
    case 'connected':
      return 'Connected';
    case 'disconnected':
      return 'Not Connected';
    case 'error':
      return 'Error';
  }
}

function providerIcon(type: string): string {
  switch (type) {
    case 'github':
      return '\u2B21';
    case 'gitlab':
      return '\u2B22';
    case 'bitbucket':
      return '\u2B23';
    case 'jira':
      return '\u2611';
    case 'teams':
      return '\u2709';
    default:
      return '\u2699';
  }
}

export function IntegrationManagement(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin', 'security-manager']}>
      <IntegrationManagementContent />
    </RequireRole>
  );
}

function IntegrationManagementContent(): React.ReactElement {
  const { data, isLoading, error } = useIntegrations();

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
          Failed to load integrations.
        </p>
      </div>
    );
  }

  const gitProviders = data.filter((i) => ['github', 'gitlab', 'bitbucket'].includes(i.type));
  const other = data.filter((i) => !['github', 'gitlab', 'bitbucket'].includes(i.type));

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
          Integrations
        </h1>
      </div>

      {/* Git Providers */}
      <div className="card">
        <div className="card-title">Git Providers</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {gitProviders.map((integration) => (
            <div
              key={integration.id}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                background: 'var(--bg-0)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '18px' }}>{providerIcon(integration.type)}</span>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-1)' }}>
                    {integration.label}
                  </div>
                  {integration.detail && (
                    <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '2px' }}>
                      {integration.detail}
                    </div>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '11px',
                    color: statusColor(integration.status),
                  }}
                >
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      background: statusColor(integration.status),
                    }}
                  />
                  {statusLabel(integration.status)}
                </span>
                <button
                  className="btn btn-outline"
                  onClick={() => {
                    if (integration.status === 'connected') {
                      alert(`Opening configuration for ${integration.label}.`);
                    } else {
                      alert(`OAuth flow for ${integration.label} will open in a new window. Configure callback URL first in Settings.`);
                    }
                  }}
                >
                  {integration.status === 'connected' ? 'Configure' : 'Connect'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Other Integrations */}
      <div className="card">
        <div className="card-title">Collaboration Tools</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {other.map((integration) => (
            <div
              key={integration.id}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                background: 'var(--bg-0)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '18px' }}>{providerIcon(integration.type)}</span>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-1)' }}>
                    {integration.label}
                  </div>
                  {integration.detail && (
                    <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '2px' }}>
                      {integration.detail}
                    </div>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '11px',
                    color: statusColor(integration.status),
                  }}
                >
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      background: statusColor(integration.status),
                    }}
                  />
                  {statusLabel(integration.status)}
                </span>
                <button
                  className="btn btn-outline"
                  onClick={() => {
                    if (integration.status === 'connected') {
                      alert(`Opening configuration for ${integration.label}.`);
                    } else {
                      alert(`OAuth flow for ${integration.label} will open in a new window. Configure callback URL first in Settings.`);
                    }
                  }}
                >
                  {integration.status === 'connected' ? 'Configure' : 'Connect'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
