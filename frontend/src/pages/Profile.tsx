import { useState } from 'react';
import { useAuth } from '@/lib/auth.tsx';
import { ROLE_LABELS } from '@/lib/roles.ts';
import { applyTheme, getStoredTheme, type Theme } from '@/lib/themes.ts';
import { cn } from '@/lib/utils.ts';

type ProfileSection = 'appearance' | 'notifications' | 'security' | 'api-keys';

interface NotificationPref {
  event: string;
  inApp: boolean;
  email: boolean;
}

const NOTIFICATION_PREFS: NotificationPref[] = [
  { event: 'Critical findings detected', inApp: true, email: true },
  { event: 'Scan completed', inApp: true, email: false },
  { event: 'Policy violations on PR', inApp: true, email: true },
  { event: 'Suppression request updates', inApp: true, email: false },
  { event: 'Certificate expiry warnings', inApp: true, email: true },
  { event: 'Compliance score changes', inApp: true, email: false },
];

interface ApiKey {
  name: string;
  scopes: string;
  created: string;
  lastUsed: string;
}

const MOCK_API_KEYS: ApiKey[] = [
  { name: 'Local development', scopes: 'scan:write, cbom:read', created: '2026-03-18', lastUsed: '1h ago' },
];

interface ThemeOptionDef {
  id: Theme;
  label: string;
  color: string;
}

const THEME_OPTIONS: ThemeOptionDef[] = [
  { id: 'radar', label: 'Radar (SOC Dark)', color: '#06b6d4' },
  { id: 'crystal', label: 'Crystal (Clean SaaS)', color: '#667eea' },
  { id: 'sentinel', label: 'Sentinel (Data Dense)', color: '#f59e0b' },
];

export function Profile(): React.ReactElement {
  const { user } = useAuth();
  const [activeSection, setActiveSection] = useState<ProfileSection>('appearance');
  const [currentTheme, setCurrentTheme] = useState<Theme>(getStoredTheme);

  const handleThemeChange = (theme: Theme): void => {
    setCurrentTheme(theme);
    applyTheme(theme);
  };

  const sidebarItems: { key: ProfileSection; label: string }[] = [
    { key: 'appearance', label: 'Appearance' },
    { key: 'notifications', label: 'Notifications' },
    { key: 'security', label: 'Security' },
    { key: 'api-keys', label: 'My API Keys' },
  ];

  return (
    <div>
      <div style={{ marginBottom: '20px' }}>
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
            letterSpacing: '0.04em',
          }}
        >
          My Profile
        </h1>
      </div>

      <div style={{ display: 'flex', gap: '20px' }}>
        {/* Sidebar nav */}
        <div style={{ width: '180px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
          {sidebarItems.map((item) => (
            <div
              key={item.key}
              role="button"
              tabIndex={0}
              onClick={() => setActiveSection(item.key)}
              style={{
                padding: '7px 12px',
                borderRadius: 'var(--radius)',
                background: activeSection === item.key ? 'var(--accent-dim)' : 'transparent',
                color: activeSection === item.key ? 'var(--accent)' : 'var(--text-2)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              {item.label}
            </div>
          ))}
        </div>

        {/* Content */}
        <div style={{ flex: 1 }}>
          {/* Account card — always visible */}
          <div className="card">
            <div className="card-title">Account</div>
            <div className="g2" style={{ marginBottom: 0 }}>
              <div className="field">
                <label className="field-label">Name</label>
                <input className="input" defaultValue={user?.name ?? 'User'} readOnly />
              </div>
              <div className="field">
                <label className="field-label">Email</label>
                <input className="input" defaultValue={user?.email ?? ''} readOnly />
              </div>
              <div className="field">
                <label className="field-label">Role</label>
                <input
                  className="input"
                  value={user ? ROLE_LABELS[user.role] : ''}
                  disabled
                  style={{ opacity: 0.6 }}
                  readOnly
                />
              </div>
              <div className="field">
                <label className="field-label">Member since</label>
                <input
                  className="input"
                  value="2026-03-15"
                  disabled
                  style={{ opacity: 0.6 }}
                  readOnly
                />
              </div>
            </div>
          </div>

          {/* Theme picker */}
          {activeSection === 'appearance' && (
            <div className="card">
              <div className="card-title">Theme</div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {THEME_OPTIONS.map((opt) => (
                  <div
                    key={opt.id}
                    role="button"
                    tabIndex={0}
                    className={cn('theme-option', currentTheme === opt.id && 'active')}
                    onClick={() => handleThemeChange(opt.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <div
                      className="theme-dot"
                      style={{ background: opt.color, width: '12px', height: '12px', borderRadius: '50%', border: '1px solid var(--border)' }}
                    />
                    {opt.label}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Notification preferences */}
          {activeSection === 'notifications' && (
            <div className="card">
              <div className="card-title">Notification Preferences</div>
              <table>
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>In-App</th>
                    <th>Email</th>
                  </tr>
                </thead>
                <tbody>
                  {NOTIFICATION_PREFS.map((pref) => (
                    <tr key={pref.event}>
                      <td>{pref.event}</td>
                      <td style={{ color: pref.inApp ? 'var(--green)' : 'var(--text-4)' }}>
                        {pref.inApp ? 'On' : 'Off'}
                      </td>
                      <td style={{ color: pref.email ? 'var(--green)' : 'var(--text-4)' }}>
                        {pref.email ? 'On' : 'Off'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Security */}
          {activeSection === 'security' && (
            <div className="card">
              <div className="card-title">Security</div>
              <div className="g2" style={{ marginBottom: 0 }}>
                <div className="field">
                  <label className="field-label">Change Password</label>
                  <input className="input" type="password" placeholder="New password" />
                </div>
                <div className="field">
                  <label className="field-label">Confirm Password</label>
                  <input className="input" type="password" placeholder="Confirm" />
                </div>
              </div>
              <div style={{ marginTop: '12px' }}>
                <button className="btn btn-outline" onClick={() => alert('MFA setup requires backend integration. Coming in a future release.')}>Enable MFA</button>
              </div>
            </div>
          )}

          {/* API Keys */}
          {activeSection === 'api-keys' && (
            <div className="card">
              <div className="card-title">My API Keys</div>
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Scopes</th>
                    <th>Created</th>
                    <th>Last Used</th>
                  </tr>
                </thead>
                <tbody>
                  {MOCK_API_KEYS.map((key) => (
                    <tr key={key.name}>
                      <td>{key.name}</td>
                      <td>{key.scopes}</td>
                      <td>{key.created}</td>
                      <td>{key.lastUsed}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div style={{ marginTop: '10px' }}>
                <button className="btn btn-outline" onClick={() => alert('API key generation requires backend integration. Coming in a future release.')}>+ Create API Key</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
