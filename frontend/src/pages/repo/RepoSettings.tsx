import { useState } from 'react';
import { useParams } from '@tanstack/react-router';

type SettingsSection = 'general' | 'scan-sources' | 'schedule' | 'jira' | 'notifications';

export function RepoSettings(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const [section, setSection] = useState<SettingsSection>('general');

  const sections: { key: SettingsSection; label: string }[] = [
    { key: 'general', label: 'General' },
    { key: 'scan-sources', label: 'Scan Sources' },
    { key: 'schedule', label: 'Schedule' },
    { key: 'jira', label: 'Jira' },
    { key: 'notifications', label: 'Notifications' },
  ];

  return (
    <div>
      <h1
        style={{
          fontSize: '18px',
          fontWeight: 700,
          textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
          letterSpacing: '0.04em',
          marginBottom: '16px',
        }}
      >
        Settings
      </h1>

      <div
        style={{
          display: 'flex',
          gap: '4px',
          marginBottom: '20px',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '8px',
        }}
      >
        {sections.map((s) => (
          <button
            key={s.key}
            className={`btn ${section === s.key ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setSection(s.key)}
            data-testid={`settings-section-${s.key}`}
            style={{ fontSize: '12px', padding: '4px 12px' }}
          >
            {s.label}
          </button>
        ))}
      </div>

      {section === 'general' && (
        <div className="card">
          <div className="card-title">General Settings</div>
          <p style={{ color: 'var(--text-3)', fontSize: '13px', padding: '12px 0' }}>
            Project <strong>{repoId}</strong> configuration. Manage project name, description, and
            default scan options.
          </p>
        </div>
      )}

      {section === 'scan-sources' && (
        <div className="card">
          <div className="card-title">Scan Sources</div>
          <p style={{ color: 'var(--text-3)', fontSize: '13px', padding: '12px 0' }}>
            Configure repository connections, branches, and scan triggers for this project.
          </p>
        </div>
      )}

      {section === 'schedule' && (
        <div className="card">
          <div className="card-title">Scan Schedule</div>
          <p style={{ color: 'var(--text-3)', fontSize: '13px', padding: '12px 0' }}>
            Set up automated scan schedules. Scans can run on a cron schedule or be triggered by
            events.
          </p>
        </div>
      )}

      {section === 'jira' && (
        <div className="card">
          <div className="card-title">Jira Integration</div>
          <p style={{ color: 'var(--text-3)', fontSize: '13px', padding: '12px 0' }}>
            Configure Jira project mapping, issue type, and field mappings for this project.
          </p>
        </div>
      )}

      {section === 'notifications' && (
        <div className="card">
          <div className="card-title">Notification Settings</div>
          <p style={{ color: 'var(--text-3)', fontSize: '13px', padding: '12px 0' }}>
            Configure scan completion notifications, severity thresholds, and delivery channels for
            this project.
          </p>
        </div>
      )}
    </div>
  );
}
