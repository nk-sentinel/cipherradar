import { useState } from 'react';
import { useAuth } from '@/lib/auth.tsx';
import { ROLE_LABELS } from '@/lib/roles.ts';
import { applyTheme, getStoredTheme, type Theme } from '@/lib/themes.ts';
import { cn } from '@/lib/utils.ts';
import { PasswordChangeForm } from '@/components/profile/PasswordChangeForm.tsx';
import { ApiKeyManager } from '@/components/profile/ApiKeyManager.tsx';

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

interface ThemeOptionDef {
  id: Theme;
  label: string;
  accent: string;
  bg: string;
  sidebar: string;
  content: string;
}

const THEME_OPTIONS: ThemeOptionDef[] = [
  { id: 'radar', label: 'Radar (SOC Dark)', accent: '#06b6d4', bg: '#05080f', sidebar: '#0a0f1a', content: '#0d1520' },
  { id: 'crystal', label: 'Crystal (Clean SaaS)', accent: '#667eea', bg: '#f5f6f8', sidebar: '#fff', content: '#fafbfc' },
  { id: 'sentinel', label: 'Sentinel (Data Dense)', accent: '#f59e0b', bg: '#0c0c0c', sidebar: '#111', content: '#161616' },
];

export function Profile(): React.ReactElement {
  const { user } = useAuth();
  const [activeSection, setActiveSection] = useState<ProfileSection>('appearance');
  const [currentTheme, setCurrentTheme] = useState<Theme>(getStoredTheme);

  // Determine auth source. In Phase 4.5, the User model doesn't have authSource yet,
  // so we default to 'local' unless user object has it.
  const authSource = (user as Record<string, unknown> | null)?.authSource as string | undefined ?? 'local';

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
                  value={(user as Record<string, unknown> | null)?.createdAt ? new Date(String((user as Record<string, unknown>).createdAt)).toLocaleDateString() : 'N/A'}
                  disabled
                  style={{ opacity: 0.6 }}
                  readOnly
                />
              </div>
              <div className="field">
                <label className="field-label">Auth Source</label>
                <input
                  className="input"
                  value={authSource === 'local' ? 'Local (email/password)' : authSource}
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
                    data-testid={`theme-option-${opt.id}`}
                    style={{ cursor: 'pointer' }}
                  >
                    <div className="theme-preview" style={{ border: currentTheme === opt.id ? `1px solid ${opt.accent}` : undefined }}>
                      <div className="theme-preview-sidebar" style={{ background: opt.sidebar }} />
                      <div className="theme-preview-content" style={{ background: opt.content }}>
                        <div className="theme-preview-line" style={{ background: opt.accent, width: '80%' }} />
                        <div className="theme-preview-line" style={{ background: opt.accent, width: '50%', opacity: 0.5 }} />
                      </div>
                    </div>
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
                    <th scope="col">Event</th>
                    <th scope="col">In-App</th>
                    <th scope="col">Email</th>
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
            <>
              <PasswordChangeForm authSource={authSource} />

              {/* MFA button — disabled, Phase 6 */}
              <div className="card">
                <div className="card-title">Multi-Factor Authentication</div>
                <div style={{ position: 'relative', display: 'inline-block' }}>
                  <button
                    className="btn btn-outline"
                    disabled
                    title="MFA will be available in Phase 6 (Identity & SSO)"
                    data-testid="mfa-btn"
                    style={{ opacity: 0.5 }}
                  >
                    Enable MFA
                  </button>
                  <span
                    style={{
                      marginLeft: '8px',
                      fontSize: '11px',
                      color: 'var(--text-3)',
                    }}
                  >
                    Available in Phase 6
                  </span>
                </div>
              </div>
            </>
          )}

          {/* API Keys */}
          {activeSection === 'api-keys' && <ApiKeyManager />}
        </div>
      </div>
    </div>
  );
}
