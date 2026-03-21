import { useState, useEffect } from 'react';
import {
  useNotificationPreferences,
  useUpdateNotificationPreferences,
} from '@/api/hooks/useNotifications.ts';
import type { NotificationPreferencesData } from '@/mocks/data/notifications.ts';

export function NotificationPreferences(): React.ReactElement {
  const { data, isLoading, error } = useNotificationPreferences();
  const updatePrefs = useUpdateNotificationPreferences();
  const [localPrefs, setLocalPrefs] = useState<NotificationPreferencesData | null>(null);
  const [teamsUrl, setTeamsUrl] = useState('');

  useEffect(() => {
    if (data && !localPrefs) {
      setLocalPrefs(data);
      setTeamsUrl(data.teamsWebhookUrl);
    }
  }, [data, localPrefs]);

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
          Failed to load notification preferences.
        </p>
      </div>
    );
  }

  const prefs = localPrefs ?? data;

  const togglePref = (trigger: string, channel: 'inApp' | 'email') => {
    setLocalPrefs((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        preferences: prev.preferences.map((p) =>
          p.trigger === trigger ? { ...p, [channel]: !p[channel] } : p,
        ),
      };
    });
  };

  const handleSave = () => {
    if (!localPrefs) return;
    const toSave = { ...localPrefs, teamsWebhookUrl: teamsUrl };
    updatePrefs.mutate(toSave);
    setLocalPrefs(toSave);
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
          Notification Preferences
        </h1>
        <button className="btn btn-accent" onClick={handleSave}>
          Save Changes
        </button>
      </div>

      {/* Per-trigger toggles */}
      <div className="card" style={{ marginBottom: '16px' }}>
        <div className="card-title">Alert Triggers</div>
        <table>
          <thead>
            <tr>
              <th>Trigger</th>
              <th>Description</th>
              <th style={{ textAlign: 'center' }}>In-App</th>
              <th style={{ textAlign: 'center' }}>Email</th>
            </tr>
          </thead>
          <tbody>
            {prefs.preferences.map((pref) => (
              <tr key={pref.trigger}>
                <td>
                  <strong>{pref.label}</strong>
                </td>
                <td style={{ color: 'var(--text-3)' }}>{pref.description}</td>
                <td style={{ textAlign: 'center' }}>
                  <ToggleSwitch
                    checked={pref.inApp}
                    onChange={() => togglePref(pref.trigger, 'inApp')}
                    label={`${pref.label} in-app`}
                  />
                </td>
                <td style={{ textAlign: 'center' }}>
                  <ToggleSwitch
                    checked={pref.email}
                    onChange={() => togglePref(pref.trigger, 'email')}
                    label={`${pref.label} email`}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Integrations */}
      <div className="g2">
        {/* Jira connection */}
        <div className="card">
          <div className="card-title">Jira Integration</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: prefs.jiraConnected ? 'var(--green)' : 'var(--red)',
                display: 'inline-block',
              }}
            />
            <span style={{ fontSize: '12px', color: 'var(--text-1)' }}>
              {prefs.jiraConnected ? 'Connected' : 'Not Connected'}
            </span>
          </div>
          {prefs.jiraBaseUrl && (
            <div style={{ fontSize: '11px', color: 'var(--text-3)' }}>
              {prefs.jiraBaseUrl}
            </div>
          )}
          <div style={{ marginTop: '10px' }}>
            <button
              className="btn btn-outline"
              onClick={() => alert('Jira configuration requires admin access. Go to Settings > Integrations to manage your Jira connection.')}
            >
              Configure
            </button>
          </div>
        </div>

        {/* Teams webhook */}
        <div className="card">
          <div className="card-title">Microsoft Teams Webhook</div>
          <div className="field">
            <label className="field-label" htmlFor="teams-webhook">
              Webhook URL
            </label>
            <input
              id="teams-webhook"
              className="input"
              type="url"
              value={teamsUrl}
              onChange={(e) => setTeamsUrl(e.target.value)}
              placeholder="https://outlook.office.com/webhook/..."
            />
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-4)' }}>
            Notifications matching your in-app triggers will also be sent to this Teams channel.
          </div>
        </div>
      </div>
    </div>
  );
}

function ToggleSwitch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: () => void;
  label: string;
}): React.ReactElement {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={onChange}
      style={{
        width: '34px',
        height: '18px',
        borderRadius: '9px',
        background: checked ? 'var(--accent)' : 'var(--bg-3)',
        border: '1px solid var(--border)',
        cursor: 'pointer',
        position: 'relative',
        transition: 'background 0.15s',
        padding: 0,
      }}
    >
      <span
        style={{
          width: '12px',
          height: '12px',
          borderRadius: '50%',
          background: checked ? 'var(--bg-0)' : 'var(--text-4)',
          position: 'absolute',
          top: '2px',
          left: checked ? '18px' : '2px',
          transition: 'left 0.15s',
        }}
      />
    </button>
  );
}
