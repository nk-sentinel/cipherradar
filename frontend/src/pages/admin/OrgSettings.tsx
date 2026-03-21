import { useState, useEffect } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useOrgSettings, useSaveOrgSettings } from '@/api/hooks/useAdmin.ts';

export function OrgSettings(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin', 'security-manager']}>
      <OrgSettingsContent />
    </RequireRole>
  );
}

function OrgSettingsContent(): React.ReactElement {
  const { data, isLoading, error } = useOrgSettings();
  const saveSettings = useSaveOrgSettings();
  const [orgName, setOrgName] = useState('');
  const [autoScan, setAutoScan] = useState(false);
  const [scanOnPr, setScanOnPr] = useState(false);
  const [policyFile, setPolicyFile] = useState('');
  const [failOnSeverity, setFailOnSeverity] = useState<'critical' | 'high' | 'medium' | 'low' | 'none'>('high');
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setOrgName(data.name);
      setAutoScan(data.defaultScanConfig.autoScan);
      setScanOnPr(data.defaultScanConfig.scanOnPr);
      setPolicyFile(data.defaultScanConfig.policyFile);
      setFailOnSeverity(data.defaultScanConfig.failOnSeverity);
    }
  }, [data]);

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
          Failed to load organization settings.
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
          Organization Settings
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {saveMessage && (
            <span style={{ fontSize: '12px', color: 'var(--green)' }}>{saveMessage}</span>
          )}
          <button
            className="btn btn-accent"
            disabled={saveSettings.isPending}
            onClick={() => {
              setSaveMessage(null);
              saveSettings.mutate(
                {
                  name: orgName,
                  plan: data!.plan,
                  defaultScanConfig: {
                    autoScan,
                    scanOnPr,
                    policyFile,
                    failOnSeverity,
                  },
                },
                {
                  onSuccess: () => setSaveMessage('Settings saved successfully.'),
                  onError: () => setSaveMessage('Failed to save settings.'),
                },
              );
            }}
          >
            {saveSettings.isPending ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>

      {/* Org info */}
      <div className="card">
        <div className="card-title">Organization</div>
        <div className="g2" style={{ marginBottom: 0 }}>
          <div className="field">
            <label className="field-label">Organization Name</label>
            <input
              className="input"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Plan</label>
            <input
              className="input"
              value={data.plan.charAt(0).toUpperCase() + data.plan.slice(1)}
              disabled
              style={{ opacity: 0.6 }}
              readOnly
            />
          </div>
        </div>
      </div>

      {/* Default scan configuration */}
      <div className="card">
        <div className="card-title">Default Scan Configuration</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <input
              type="checkbox"
              id="auto-scan"
              checked={autoScan}
              onChange={(e) => setAutoScan(e.target.checked)}
              style={{ accentColor: 'var(--accent)' }}
            />
            <label htmlFor="auto-scan" style={{ fontSize: '12px', color: 'var(--text-1)', cursor: 'pointer' }}>
              Enable automatic scanning on repository import
            </label>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <input
              type="checkbox"
              id="scan-on-pr"
              checked={scanOnPr}
              onChange={(e) => setScanOnPr(e.target.checked)}
              style={{ accentColor: 'var(--accent)' }}
            />
            <label htmlFor="scan-on-pr" style={{ fontSize: '12px', color: 'var(--text-1)', cursor: 'pointer' }}>
              Scan on pull request merge
            </label>
          </div>
          <div className="g2" style={{ marginBottom: 0 }}>
            <div className="field">
              <label className="field-label">Policy File</label>
              <input
                className="input"
                value={policyFile}
                onChange={(e) => setPolicyFile(e.target.value)}
                placeholder="policy.cbom.yml"
              />
            </div>
            <div className="field">
              <label className="field-label">Fail on Severity</label>
              <select
                className="input"
                value={failOnSeverity}
                onChange={(e) => setFailOnSeverity(e.target.value as typeof failOnSeverity)}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="none">None</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
