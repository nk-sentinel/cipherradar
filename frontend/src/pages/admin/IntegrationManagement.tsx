import { useState } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import {
  useIntegrationProviders,
  useConnectProvider,
  useDisconnectProvider,
  useTestConnection,
  useDiscoverRepos,
  useImportRepos,
  type IntegrationProvider,
  type ProviderType,
} from '@/api/hooks/useIntegrations.ts';
import { useUserOrgs } from '@/api/hooks/useOrgs.ts';
import { useToast } from '@/lib/use-toast.ts';

// ---------------------------------------------------------------------------
// Exported helpers (tested in unit tests)
// ---------------------------------------------------------------------------

export const PROVIDER_SCOPES: Record<ProviderType, string[]> = {
  github: ['repo', 'read:org', 'admin:repo_hook'],
  gitlab: ['api', 'read_repository', 'read_user'],
  bitbucket: ['repository', 'pullrequest', 'webhook'],
  jira: ['read:jira-work', 'write:jira-work'],
  teams: ['ChannelMessage.Send', 'Group.ReadWrite.All'],
};

export function tokenAgeDays(ageInDays: number | null): number | null {
  return ageInDays;
}

export function shouldWarnRotation(ageInDays: number | null): boolean {
  if (ageInDays === null) return false;
  return ageInDays > 90;
}

// ---------------------------------------------------------------------------
// Visual helpers
// ---------------------------------------------------------------------------

function statusColor(status: string): string {
  switch (status) {
    case 'connected':
      return 'var(--green)';
    case 'disconnected':
      return 'var(--text-4)';
    case 'error':
      return 'var(--red)';
    default:
      return 'var(--text-4)';
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'connected':
      return 'Connected';
    case 'disconnected':
      return 'Not Connected';
    case 'error':
      return 'Error';
    default:
      return status;
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

function languageHint(lang: string | null): string {
  if (!lang) return '--';
  return lang;
}

// ---------------------------------------------------------------------------
// PAT Connect Modal
// ---------------------------------------------------------------------------

interface PATModalProps {
  providerType: ProviderType;
  providerLabel: string;
  onClose: () => void;
  onConnect: (baseUrl: string, token: string) => void;
  isPending: boolean;
  testConnection: (providerId: string) => void;
  isTestPending: boolean;
  testResult: { success: boolean; message: string } | null;
}

function PATModal({
  providerType,
  providerLabel,
  onClose,
  onConnect,
  isPending,
  testConnection,
  isTestPending,
  testResult,
}: PATModalProps): React.ReactElement {
  const [baseUrl, setBaseUrl] = useState('');
  const [token, setToken] = useState('');
  const scopes = PROVIDER_SCOPES[providerType];

  return (
    <div
      data-testid="pat-modal"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="card"
        style={{ width: '480px', maxHeight: '80vh', overflow: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-title">Connect {providerLabel}</div>

        {/* Base URL */}
        <div style={{ marginBottom: '12px' }}>
          <label className="field-label" htmlFor="pat-base-url">
            Base URL
          </label>
          <input
            id="pat-base-url"
            className="input"
            type="url"
            placeholder={
              providerType === 'github'
                ? 'https://github.com'
                : providerType === 'gitlab'
                  ? 'https://gitlab.com'
                  : `https://${providerType}.example.com`
            }
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
          />
        </div>

        {/* Token */}
        <div style={{ marginBottom: '12px' }}>
          <label className="field-label" htmlFor="pat-token">
            Personal Access Token
          </label>
          <input
            id="pat-token"
            className="input"
            type="password"
            placeholder="Paste token here"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
        </div>

        {/* Required scopes */}
        <div style={{ marginBottom: '16px' }}>
          <div className="field-label">Required Scopes</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {scopes.map((scope) => (
              <span
                key={scope}
                style={{
                  fontSize: '10px',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-2)',
                  fontFamily: 'var(--font-mono, monospace)',
                }}
              >
                {scope}
              </span>
            ))}
          </div>
        </div>

        {/* Test result */}
        {testResult && (
          <div
            className={`alert ${testResult.success ? 'alert-success' : 'alert-error'}`}
            style={{ marginBottom: '12px', fontSize: '12px' }}
          >
            {testResult.message}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-outline"
            disabled={!baseUrl || !token || isTestPending}
            onClick={() => testConnection(providerType)}
            data-testid="test-connection-btn"
          >
            {isTestPending ? 'Testing...' : 'Test Connection'}
          </button>
          <button
            className="btn btn-accent"
            disabled={!baseUrl || !token || isPending}
            onClick={() => onConnect(baseUrl, token)}
          >
            {isPending ? 'Connecting...' : 'Connect'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Repo Picker Modal
// ---------------------------------------------------------------------------

interface RepoPickerProps {
  providerId: string;
  providerLabel: string;
  onClose: () => void;
}

function RepoPicker({ providerId, providerLabel, onClose }: RepoPickerProps): React.ReactElement {
  const [search, setSearch] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [autoScan, setAutoScan] = useState(true);
  const [groupId, setGroupId] = useState<string | null>(null);
  const { toast } = useToast();
  const { data: repos, isLoading } = useDiscoverRepos(providerId, search);
  const { data: orgs } = useUserOrgs();
  const importRepos = useImportRepos();

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleImport = () => {
    importRepos.mutate(
      { providerType: 'github', repoIds: Array.from(selectedIds), groupId, autoScan },
      {
        onSuccess: (result) => {
          toast({
            title: `Imported ${String(result.imported)} repositories`,
            variant: 'success',
          });
          onClose();
        },
        onError: () => {
          toast({ title: 'Failed to import repos', variant: 'error' });
        },
      },
    );
  };

  return (
    <div
      data-testid="repo-picker-modal"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="card"
        style={{ width: '560px', maxHeight: '80vh', overflow: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-title">Import Repositories from {providerLabel}</div>

        {/* Search */}
        <div style={{ marginBottom: '12px' }}>
          <input
            className="input"
            type="text"
            placeholder="Search repositories..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search repositories"
          />
        </div>

        {/* Repo list */}
        <div
          style={{
            maxHeight: '300px',
            overflow: 'auto',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            marginBottom: '12px',
          }}
        >
          {isLoading && (
            <div style={{ padding: '12px', color: 'var(--text-3)', fontSize: '12px' }}>
              Loading repositories...
            </div>
          )}
          {repos && repos.length === 0 && (
            <div style={{ padding: '12px', color: 'var(--text-3)', fontSize: '12px' }}>
              No repositories found.
            </div>
          )}
          {repos?.map((repo) => (
            <div
              key={repo.id}
              data-testid={`repo-row-${repo.id}`}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '8px 12px',
                borderBottom: '1px solid var(--border)',
                background: selectedIds.has(repo.id) ? 'var(--bg-2)' : 'transparent',
                opacity: repo.alreadyImported ? 0.5 : 1,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  type="checkbox"
                  checked={selectedIds.has(repo.id)}
                  disabled={repo.alreadyImported}
                  onChange={() => toggleSelect(repo.id)}
                  aria-label={`Select ${repo.fullName}`}
                />
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-1)' }}>
                    {repo.fullName}
                    {repo.private && (
                      <span
                        style={{
                          marginLeft: '6px',
                          fontSize: '9px',
                          padding: '1px 4px',
                          borderRadius: 'var(--radius)',
                          border: '1px solid var(--border)',
                          color: 'var(--text-3)',
                        }}
                      >
                        Private
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
                    {languageHint(repo.language)} / {repo.defaultBranch}
                  </div>
                </div>
              </div>
              {repo.alreadyImported && (
                <span style={{ fontSize: '10px', color: 'var(--green)' }}>Imported</span>
              )}
            </div>
          ))}
        </div>

        {/* Group selector */}
        <div style={{ marginBottom: '12px' }}>
          <label className="field-label" htmlFor="group-select">
            Import to Group
          </label>
          <select
            id="group-select"
            className="input"
            value={groupId ?? ''}
            onChange={(e) => setGroupId(e.target.value || null)}
            data-testid="group-select"
          >
            <option value="">No group (root)</option>
            {orgs?.map((org) => (
              <option key={org.id} value={org.id}>
                {org.name}
              </option>
            ))}
          </select>
        </div>

        {/* Auto-scan toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <input
            type="checkbox"
            id="auto-scan-toggle"
            checked={autoScan}
            onChange={() => setAutoScan(!autoScan)}
          />
          <label htmlFor="auto-scan-toggle" style={{ fontSize: '12px', color: 'var(--text-2)' }}>
            Enable auto-scan on import
          </label>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-accent"
            disabled={selectedIds.size === 0 || importRepos.isPending}
            onClick={handleImport}
          >
            {importRepos.isPending
              ? 'Importing...'
              : `Import ${String(selectedIds.size)} Repo${selectedIds.size !== 1 ? 's' : ''}`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Provider Card
// ---------------------------------------------------------------------------

interface ProviderCardProps {
  provider: IntegrationProvider;
  onConnect: () => void;
  onDisconnect: () => void;
  onBrowseRepos: () => void;
  onResync?: () => void;
  isResyncing?: boolean;
}

function ProviderCard({ provider, onConnect, onDisconnect, onBrowseRepos, onResync, isResyncing }: ProviderCardProps): React.ReactElement {
  const isGit = ['github', 'gitlab', 'bitbucket'].includes(provider.type);
  const connected = provider.status === 'connected';

  return (
    <div
      data-testid={`provider-card-${provider.type}`}
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '14px',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--bg-0)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span style={{ fontSize: '20px' }}>{providerIcon(provider.type)}</span>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-1)' }}>
            {provider.label}
          </div>
          {provider.detail && (
            <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '2px' }}>
              {provider.detail}
            </div>
          )}
          {/* Synced repos count (#85) */}
          {isGit && connected && (
            <div
              data-testid={`synced-count-${provider.type}`}
              style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}
            >
              {provider.syncedRepoCount} synced repos
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {/* Token age + rotation warning (#86) */}
        {connected && provider.tokenAge !== null && (
          <span
            data-testid={`token-age-${provider.type}`}
            style={{
              fontSize: '10px',
              color: provider.tokenRotationWarning ? 'var(--orange)' : 'var(--text-3)',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
            }}
          >
            {provider.tokenRotationWarning && (
              <span title="Token rotation recommended" style={{ fontSize: '12px' }}>{'\u26A0'}</span>
            )}
            Token: {provider.tokenAge}d old
          </span>
        )}

        {/* Status indicator */}
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            fontSize: '11px',
            color: statusColor(provider.status),
          }}
        >
          <span
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: statusColor(provider.status),
            }}
          />
          {statusLabel(provider.status)}
        </span>

        {/* Actions */}
        {connected ? (
          <div style={{ display: 'flex', gap: '4px' }}>
            {isGit && (
              <button className="btn btn-outline" onClick={onBrowseRepos} style={{ fontSize: '11px', padding: '4px 8px' }}>
                Browse Repos
              </button>
            )}
            {isGit && onResync && (
              <button
                className="btn btn-outline"
                onClick={onResync}
                disabled={isResyncing}
                style={{ fontSize: '11px', padding: '4px 8px' }}
                data-testid={`resync-btn-${provider.type}`}
              >
                {isResyncing ? 'Syncing...' : 'Re-sync'}
              </button>
            )}
            <button
              className="btn btn-outline"
              onClick={onDisconnect}
              style={{ fontSize: '11px', padding: '4px 8px', color: 'var(--red)' }}
            >
              Disconnect
            </button>
          </div>
        ) : (
          <button className="btn btn-accent" onClick={onConnect} style={{ fontSize: '11px', padding: '4px 10px' }}>
            Connect
          </button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function IntegrationManagement(): React.ReactElement {
  return (
    <RequireRole
      roles={['org-admin', 'security-manager']}
      fallback={
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
            Access denied. You do not have permission to manage integrations. Contact your admin.
          </p>
        </div>
      }
    >
      <IntegrationManagementContent />
    </RequireRole>
  );
}

function IntegrationManagementContent(): React.ReactElement {
  const { data, isLoading, error } = useIntegrationProviders();
  const connectProvider = useConnectProvider();
  const disconnectProvider = useDisconnectProvider();
  const testConnection = useTestConnection();
  const { toast } = useToast();

  const [patModal, setPATModal] = useState<{ type: ProviderType; label: string } | null>(null);
  const [repoPickerProvider, setRepoPickerProvider] = useState<IntegrationProvider | null>(null);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [resyncingId, setResyncingId] = useState<string | null>(null);
  // H19: TODO — full New Project flow for vendor/non-git repos. For now, show "Coming soon" message.
  const [showNewProjectMsg, setShowNewProjectMsg] = useState(false);

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
  const otherProviders = data.filter((i) => !['github', 'gitlab', 'bitbucket'].includes(i.type));

  const handleConnect = (baseUrl: string, token: string) => {
    if (!patModal) return;
    connectProvider.mutate(
      { type: patModal.type, baseUrl, token },
      {
        onSuccess: () => {
          toast({ title: `${patModal.label} connected successfully`, variant: 'success' });
          setPATModal(null);
          setTestResult(null);
        },
        onError: () => {
          toast({ title: 'Failed to connect provider', variant: 'error' });
        },
      },
    );
  };

  const handleDisconnect = (provider: IntegrationProvider) => {
    if (!confirm(`Disconnect ${provider.label}? This will remove the stored token.`)) return;
    disconnectProvider.mutate(
      { providerId: provider.id },
      {
        onSuccess: () => {
          toast({ title: `${provider.label} disconnected`, variant: 'warning' });
        },
        onError: () => {
          toast({ title: 'Failed to disconnect', variant: 'error' });
        },
      },
    );
  };

  const handleTestConnection = (providerId: string) => {
    testConnection.mutate(
      { providerId },
      {
        onSuccess: (result) => setTestResult(result),
        onError: () => setTestResult({ success: false, message: 'Connection test failed' }),
      },
    );
  };

  const handleResync = (provider: IntegrationProvider) => {
    setResyncingId(provider.id);
    // Trigger a discover repos call to refresh the repo list from the provider
    void fetch(`/api/v1/admin/integrations/${provider.id}/repos`)
      .then(() => {
        toast({ title: `${provider.label} repositories re-synced`, variant: 'success' });
      })
      .catch(() => {
        toast({ title: `Failed to re-sync ${provider.label}`, variant: 'error' });
      })
      .finally(() => {
        setResyncingId(null);
      });
  };

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
        <button
          className="btn btn-accent"
          onClick={() => setShowNewProjectMsg(true)}
          data-testid="new-project-btn"
          style={{ fontSize: '12px' }}
        >
          + New Project
        </button>
      </div>

      {/* H19: New Project placeholder — full vendor/non-git flow is a future feature */}
      {showNewProjectMsg && (
        <div
          className="card"
          style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          data-testid="new-project-coming-soon"
        >
          <p style={{ fontSize: '12px', color: 'var(--text-2)', margin: 0 }}>
            Coming soon — use the CLI for vendor/non-git projects:{' '}
            <code style={{ fontSize: '11px' }}>cradar scan /path --push</code>
          </p>
          <button
            className="btn btn-outline"
            onClick={() => setShowNewProjectMsg(false)}
            style={{ fontSize: '11px', padding: '4px 8px' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Git Providers */}
      <div className="card">
        <div className="card-title">Git Providers</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {gitProviders.map((provider) => (
            <ProviderCard
              key={provider.id}
              provider={provider}
              onConnect={() => setPATModal({ type: provider.type, label: provider.label })}
              onDisconnect={() => handleDisconnect(provider)}
              onBrowseRepos={() => setRepoPickerProvider(provider)}
              onResync={() => handleResync(provider)}
              isResyncing={resyncingId === provider.id}
            />
          ))}
        </div>
      </div>

      {/* Collaboration Tools */}
      <div className="card">
        <div className="card-title">Collaboration Tools</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {otherProviders.map((provider) => (
            <ProviderCard
              key={provider.id}
              provider={provider}
              onConnect={() => setPATModal({ type: provider.type, label: provider.label })}
              onDisconnect={() => handleDisconnect(provider)}
              onBrowseRepos={() => {}}
            />
          ))}
        </div>
      </div>

      {/* PAT Modal */}
      {patModal && (
        <PATModal
          providerType={patModal.type}
          providerLabel={patModal.label}
          onClose={() => { setPATModal(null); setTestResult(null); }}
          onConnect={handleConnect}
          isPending={connectProvider.isPending}
          testConnection={handleTestConnection}
          isTestPending={testConnection.isPending}
          testResult={testResult}
        />
      )}

      {/* Repo Picker */}
      {repoPickerProvider && (
        <RepoPicker
          providerId={repoPickerProvider.id}
          providerLabel={repoPickerProvider.label}
          onClose={() => setRepoPickerProvider(null)}
        />
      )}
    </div>
  );
}
