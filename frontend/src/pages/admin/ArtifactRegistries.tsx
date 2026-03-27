import { useState } from 'react';
import {
  useRegistries,
  useCreateRegistry,
  useDeleteRegistry,
  useTestConnection,
  type Registry,
  type CreateRegistryParams,
} from '@/api/hooks/useRegistries';

const REGISTRY_TYPES = [
  { value: 'jfrog', label: 'JFrog Artifactory' },
  { value: 'ecr', label: 'AWS ECR' },
  { value: 'gcr', label: 'Google GCR' },
  { value: 'acr', label: 'Azure ACR' },
  { value: 'docker_hub', label: 'Docker Hub' },
  { value: 'harbor', label: 'Harbor' },
  { value: 'gitlab', label: 'GitLab Registry' },
  { value: 'custom', label: 'Custom' },
];

const AUTH_METHODS = [
  { value: 'token', label: 'Token' },
  { value: 'userpass', label: 'Username / Password' },
  { value: 'iam_role', label: 'IAM Role (AWS)' },
  { value: 'service_account', label: 'Service Account (GCP)' },
];

function AddRegistryModal({ onClose }: { onClose: () => void }) {
  const createMutation = useCreateRegistry();
  const [name, setName] = useState('');
  const [registryType, setRegistryType] = useState('jfrog');
  const [url, setUrl] = useState('');
  const [authMethod, setAuthMethod] = useState('token');

  function handleSubmit() {
    if (!name || !url) return;
    const params: CreateRegistryParams = {
      name,
      registryType,
      url,
      authMethod,
    };
    createMutation.mutate(params, { onSuccess: () => onClose() });
  }

  return (
    <div
      data-testid="add-registry-modal"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="card" style={{ width: '480px', padding: '24px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-1)', marginBottom: '16px' }}>
          Add Registry
        </h2>

        <div style={{ marginBottom: '12px' }}>
          <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
            Name
          </label>
          <input
            data-testid="registry-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Production JFrog"
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: '13px',
              background: 'var(--bg-2)',
              color: 'var(--text-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
            }}
          />
        </div>

        <div style={{ marginBottom: '12px' }}>
          <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
            Type
          </label>
          <select
            data-testid="registry-type"
            value={registryType}
            onChange={(e) => setRegistryType(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: '13px',
              background: 'var(--bg-2)',
              color: 'var(--text-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
            }}
          >
            {REGISTRY_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
            URL
          </label>
          <input
            data-testid="registry-url"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://registry.example.com"
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: '13px',
              background: 'var(--bg-2)',
              color: 'var(--text-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
            }}
          />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
            Auth Method
          </label>
          <select
            data-testid="registry-auth"
            value={authMethod}
            onChange={(e) => setAuthMethod(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 10px',
              fontSize: '13px',
              background: 'var(--bg-2)',
              color: 'var(--text-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
            }}
          >
            {AUTH_METHODS.map((m) => (
              <option key={m.value} value={m.value}>{m.label}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button className="btn btn-outline" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            data-testid="registry-submit"
            className="btn btn-accent"
            onClick={handleSubmit}
            disabled={createMutation.isPending || !name || !url}
            type="button"
          >
            {createMutation.isPending ? 'Adding...' : 'Add Registry'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function ArtifactRegistries(): React.ReactElement {
  const { data: registries, isLoading, error } = useRegistries();
  const deleteMutation = useDeleteRegistry();
  const testMutation = useTestConnection();
  const [showAddModal, setShowAddModal] = useState(false);

  return (
    <div>
      <div className="topbar">
        <h1 style={{ fontSize: '18px', fontWeight: 700 }}>Artifact Registries</h1>
        <div className="topbar-right">
          <button
            data-testid="add-registry-btn"
            className="btn btn-accent"
            onClick={() => setShowAddModal(true)}
            type="button"
          >
            Add Registry
          </button>
        </div>
      </div>

      {isLoading && (
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading registries...</p>
        </div>
      )}

      {error && (
        <div className="card">
          <p style={{ color: 'var(--red)', fontSize: '13px' }}>Failed to load registries.</p>
        </div>
      )}

      {!isLoading && !error && (
        <div className="card">
          <table data-testid="registries-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>URL</th>
                <th>Status</th>
                <th>Last Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(!registries || registries.length === 0) && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)', padding: '24px' }}>
                    No registries configured
                  </td>
                </tr>
              )}
              {registries?.map((reg: Registry) => (
                <tr key={reg.id} data-testid={`registry-row-${reg.id}`}>
                  <td style={{ fontWeight: 600 }}>{reg.name}</td>
                  <td>
                    <span className="badge" style={{ fontSize: '10px' }}>
                      {reg.registryType}
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', fontFamily: 'monospace', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {reg.url}
                  </td>
                  <td>
                    <span className={`badge ${reg.enabled ? 'b-safe' : 'b-gray'}`}>
                      {reg.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-3)' }}>
                    {new Date(reg.updatedAt).toLocaleDateString()}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        className="btn btn-outline"
                        style={{ fontSize: '10px', padding: '2px 8px' }}
                        data-testid={`test-conn-${reg.id}`}
                        onClick={() => testMutation.mutate(reg.id)}
                        disabled={testMutation.isPending}
                        type="button"
                      >
                        Test
                      </button>
                      <button
                        className="btn btn-outline"
                        style={{ fontSize: '10px', padding: '2px 8px', color: 'var(--red)' }}
                        data-testid={`delete-reg-${reg.id}`}
                        onClick={() => deleteMutation.mutate(reg.id)}
                        disabled={deleteMutation.isPending}
                        type="button"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showAddModal && (
        <AddRegistryModal onClose={() => setShowAddModal(false)} />
      )}
    </div>
  );
}
