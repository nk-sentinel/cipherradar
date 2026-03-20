/**
 * Mock data for notifications.
 */

export type NotificationSeverity = 'critical' | 'warning' | 'info' | 'success';
export type NotificationTrigger =
  | 'new-critical-finding'
  | 'compliance-drop'
  | 'scan-complete'
  | 'suppression-request'
  | 'cert-expiry'
  | 'quantum-risk-change';

export interface Notification {
  id: string;
  message: string;
  time: string;
  createdAt: string;
  unread: boolean;
  severity: NotificationSeverity;
  trigger: NotificationTrigger;
  repo?: string;
  link?: string;
}

export interface NotificationPreference {
  trigger: NotificationTrigger;
  label: string;
  description: string;
  inApp: boolean;
  email: boolean;
}

export interface NotificationPreferencesData {
  preferences: NotificationPreference[];
  jiraConnected: boolean;
  jiraBaseUrl: string | null;
  teamsWebhookUrl: string;
}

export const MOCK_NOTIFICATIONS: Notification[] = [
  {
    id: 'n-001',
    message: 'CRITICAL: Certificate validation disabled in payment-service',
    time: '2 minutes ago',
    createdAt: '2026-03-20T10:58:00Z',
    unread: true,
    severity: 'critical',
    trigger: 'new-critical-finding',
    repo: 'payment-service',
    link: '/repos/repo-1/findings',
  },
  {
    id: 'n-002',
    message: 'Suppression request pending — auth-api SHA-1',
    time: '15 minutes ago',
    createdAt: '2026-03-20T10:45:00Z',
    unread: true,
    severity: 'warning',
    trigger: 'suppression-request',
    repo: 'auth-api',
    link: '/repos/repo-2/findings',
  },
  {
    id: 'n-003',
    message: 'Compliance score dropped: mobile-backend 52% -> 45%',
    time: '1 hour ago',
    createdAt: '2026-03-20T09:00:00Z',
    unread: true,
    severity: 'warning',
    trigger: 'compliance-drop',
    repo: 'mobile-backend',
    link: '/repos/repo-4/compliance',
  },
  {
    id: 'n-004',
    message: 'Scan completed: data-pipeline #22 — 0 critical findings',
    time: '5 hours ago',
    createdAt: '2026-03-20T05:00:00Z',
    unread: false,
    severity: 'success',
    trigger: 'scan-complete',
    repo: 'data-pipeline',
    link: '/repos/repo-3/scans',
  },
  {
    id: 'n-005',
    message: 'Certificate expiring in 30 days: payment-service TLS cert',
    time: '1 day ago',
    createdAt: '2026-03-19T10:00:00Z',
    unread: false,
    severity: 'info',
    trigger: 'cert-expiry',
    repo: 'payment-service',
    link: '/certificates',
  },
  {
    id: 'n-006',
    message: 'Quantum risk score increased: mobile-backend 58 -> 68',
    time: '2 days ago',
    createdAt: '2026-03-18T14:00:00Z',
    unread: false,
    severity: 'warning',
    trigger: 'quantum-risk-change',
    repo: 'mobile-backend',
    link: '/repos/repo-4/quantum',
  },
];

export const MOCK_NOTIFICATION_PREFERENCES: NotificationPreferencesData = {
  preferences: [
    {
      trigger: 'new-critical-finding',
      label: 'New Critical Finding',
      description: 'When a scan detects a new critical-severity finding',
      inApp: true,
      email: true,
    },
    {
      trigger: 'compliance-drop',
      label: 'Compliance Score Drop',
      description: 'When a repository compliance score drops by 5% or more',
      inApp: true,
      email: true,
    },
    {
      trigger: 'scan-complete',
      label: 'Scan Complete',
      description: 'When a scan finishes (success or failure)',
      inApp: true,
      email: false,
    },
    {
      trigger: 'suppression-request',
      label: 'Suppression Request',
      description: 'When a finding suppression is requested and needs review',
      inApp: true,
      email: true,
    },
    {
      trigger: 'cert-expiry',
      label: 'Certificate Expiry Warning',
      description: 'When a monitored certificate is nearing expiry (30/14/7 days)',
      inApp: true,
      email: false,
    },
    {
      trigger: 'quantum-risk-change',
      label: 'Quantum Risk Score Change',
      description: 'When a repository quantum risk score changes significantly',
      inApp: true,
      email: false,
    },
  ],
  jiraConnected: true,
  jiraBaseUrl: 'https://nk-sentinel.atlassian.net',
  teamsWebhookUrl: 'https://outlook.office.com/webhook/abc123',
};

export function getNotifications(): Notification[] {
  return MOCK_NOTIFICATIONS;
}

export function getNotificationPreferences(): NotificationPreferencesData {
  return MOCK_NOTIFICATION_PREFERENCES;
}
