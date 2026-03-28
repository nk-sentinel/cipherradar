/**
 * Mock data for admin pages: org settings, user management, integrations, audit log.
 */

import type { Role } from '@/lib/roles.ts';

/* ---------- Org types ---------- */

export interface Org {
  id: string;
  name: string;
  slug: string;
  plan: 'free' | 'team' | 'enterprise';
  role: Role;
}

export interface OrgSettings {
  id: string;
  name: string;
  plan: 'free' | 'team' | 'enterprise';
  defaultScanConfig: {
    autoScan: boolean;
    scanOnPr: boolean;
    policyFile: string;
    failOnSeverity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  };
  labels?: {
    groupLabel: string;
    projectLabel: string;
  };
}

/* ---------- User management types ---------- */

export interface OrgUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  lastActive: string;
  status: 'active' | 'invited' | 'disabled';
}

/* ---------- Integration types ---------- */

export type IntegrationStatus = 'connected' | 'disconnected' | 'error';

export interface Integration {
  id: string;
  type: 'github' | 'gitlab' | 'bitbucket' | 'jira' | 'teams';
  label: string;
  status: IntegrationStatus;
  connectedAt: string | null;
  detail: string | null;
}

/* ---------- Audit log types ---------- */

export type AuditAction =
  | 'user.login'
  | 'user.logout'
  | 'user.invite'
  | 'user.role_change'
  | 'scan.started'
  | 'scan.completed'
  | 'policy.updated'
  | 'settings.updated'
  | 'integration.connected'
  | 'integration.disconnected'
  | 'finding.suppressed'
  | 'cbom.exported';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user: string;
  action: AuditAction;
  resource: string;
  detail: string | null;
}

/* ---------- Mock data ---------- */

export const MOCK_ORGS: Org[] = [
  { id: 'org-1', name: 'nk-sentinel', slug: 'nk-sentinel', plan: 'enterprise', role: 'org-admin' },
  { id: 'org-2', name: 'Acme Corp', slug: 'acme-corp', plan: 'team', role: 'security-engineer' },
];

export const MOCK_ORG_SETTINGS: OrgSettings = {
  id: 'org-1',
  name: 'nk-sentinel',
  plan: 'enterprise',
  defaultScanConfig: {
    autoScan: true,
    scanOnPr: true,
    policyFile: 'policy.cbom.yml',
    failOnSeverity: 'high',
  },
};

export const MOCK_ORG_USERS: OrgUser[] = [
  {
    id: 'u-001',
    name: 'Alex Chen',
    email: 'alex.chen@nk-sentinel.io',
    role: 'org-admin',
    lastActive: '2 hours ago',
    status: 'active',
  },
  {
    id: 'u-002',
    name: 'Sarah Kim',
    email: 'sarah.kim@nk-sentinel.io',
    role: 'security-manager',
    lastActive: '5 minutes ago',
    status: 'active',
  },
  {
    id: 'u-003',
    name: 'James Liu',
    email: 'james.liu@nk-sentinel.io',
    role: 'security-engineer',
    lastActive: '1 day ago',
    status: 'active',
  },
  {
    id: 'u-004',
    name: 'Maria Garcia',
    email: 'maria.garcia@nk-sentinel.io',
    role: 'team-manager',
    lastActive: '3 hours ago',
    status: 'active',
  },
  {
    id: 'u-005',
    name: 'David Park',
    email: 'david.park@nk-sentinel.io',
    role: 'compliance-auditor',
    lastActive: '12 hours ago',
    status: 'active',
  },
  {
    id: 'u-006',
    name: 'Emily Zhao',
    email: 'emily.zhao@nk-sentinel.io',
    role: 'developer',
    lastActive: '30 minutes ago',
    status: 'active',
  },
  {
    id: 'u-007',
    name: 'Tom Nguyen',
    email: 'tom.nguyen@nk-sentinel.io',
    role: 'guest',
    lastActive: 'Never',
    status: 'invited',
  },
];

export const MOCK_INTEGRATIONS: Integration[] = [
  {
    id: 'int-1',
    type: 'github',
    label: 'GitHub',
    status: 'connected',
    connectedAt: '2026-03-10T14:00:00Z',
    detail: 'nk-sentinel organization',
  },
  {
    id: 'int-2',
    type: 'gitlab',
    label: 'GitLab',
    status: 'connected',
    connectedAt: '2026-03-12T09:30:00Z',
    detail: 'gitlab.nk-sentinel.io',
  },
  {
    id: 'int-3',
    type: 'bitbucket',
    label: 'Bitbucket',
    status: 'disconnected',
    connectedAt: null,
    detail: null,
  },
  {
    id: 'int-4',
    type: 'jira',
    label: 'Jira',
    status: 'connected',
    connectedAt: '2026-03-15T11:00:00Z',
    detail: 'https://nk-sentinel.atlassian.net',
  },
  {
    id: 'int-5',
    type: 'teams',
    label: 'Microsoft Teams',
    status: 'connected',
    connectedAt: '2026-03-16T08:00:00Z',
    detail: 'Webhook configured',
  },
];

export const MOCK_AUDIT_LOG: AuditLogEntry[] = [
  {
    id: 'al-001',
    timestamp: '2026-03-21T10:05:00Z',
    user: 'alex.chen@nk-sentinel.io',
    action: 'scan.completed',
    resource: 'payment-service',
    detail: 'Scan #45 completed with 3 critical findings',
  },
  {
    id: 'al-002',
    timestamp: '2026-03-21T09:58:00Z',
    user: 'alex.chen@nk-sentinel.io',
    action: 'scan.started',
    resource: 'payment-service',
    detail: 'Scan #45 triggered manually',
  },
  {
    id: 'al-003',
    timestamp: '2026-03-21T09:30:00Z',
    user: 'sarah.kim@nk-sentinel.io',
    action: 'policy.updated',
    resource: 'Default Policy',
    detail: 'Updated fail-on severity from medium to high',
  },
  {
    id: 'al-004',
    timestamp: '2026-03-21T08:45:00Z',
    user: 'sarah.kim@nk-sentinel.io',
    action: 'finding.suppressed',
    resource: 'auth-api / SHA-1 usage',
    detail: 'Suppressed with justification: legacy compatibility',
  },
  {
    id: 'al-005',
    timestamp: '2026-03-21T08:00:00Z',
    user: 'alex.chen@nk-sentinel.io',
    action: 'user.invite',
    resource: 'tom.nguyen@nk-sentinel.io',
    detail: 'Invited as Guest / Viewer',
  },
  {
    id: 'al-006',
    timestamp: '2026-03-20T17:30:00Z',
    user: 'james.liu@nk-sentinel.io',
    action: 'cbom.exported',
    resource: 'data-pipeline',
    detail: 'Exported CycloneDX 1.7 JSON',
  },
  {
    id: 'al-007',
    timestamp: '2026-03-20T16:00:00Z',
    user: 'alex.chen@nk-sentinel.io',
    action: 'user.role_change',
    resource: 'david.park@nk-sentinel.io',
    detail: 'Changed role from Developer to Compliance Auditor',
  },
  {
    id: 'al-008',
    timestamp: '2026-03-20T14:15:00Z',
    user: 'alex.chen@nk-sentinel.io',
    action: 'settings.updated',
    resource: 'Org Settings',
    detail: 'Enabled auto-scan on PR merge',
  },
  {
    id: 'al-009',
    timestamp: '2026-03-20T12:00:00Z',
    user: 'sarah.kim@nk-sentinel.io',
    action: 'integration.connected',
    resource: 'Microsoft Teams',
    detail: 'Webhook configured for #cipherradar-alerts',
  },
  {
    id: 'al-010',
    timestamp: '2026-03-20T10:00:00Z',
    user: 'alex.chen@nk-sentinel.io',
    action: 'user.login',
    resource: 'Session',
    detail: null,
  },
];

/* ---------- Enriched integration type (D3 #85, #86) ---------- */

export interface IntegrationEnriched extends Integration {
  syncedRepoCount: number;
  tokenAge: number | null;
  tokenRotationWarning: boolean;
}

/* ---------- Discovered repo type (D3 repo picker) ---------- */

export interface DiscoveredRepo {
  id: string;
  name: string;
  fullName: string;
  language: string | null;
  defaultBranch: string;
  lastPush: string;
  private: boolean;
  alreadyImported: boolean;
}

export const MOCK_DISCOVERED_REPOS: DiscoveredRepo[] = [
  { id: 'dr-001', name: 'auth-service', fullName: 'nk-sentinel/auth-service', language: 'Go', defaultBranch: 'main', lastPush: '2026-03-26T10:00:00Z', private: false, alreadyImported: true },
  { id: 'dr-002', name: 'payment-gateway', fullName: 'nk-sentinel/payment-gateway', language: 'Java', defaultBranch: 'main', lastPush: '2026-03-25T14:00:00Z', private: true, alreadyImported: true },
  { id: 'dr-003', name: 'data-pipeline', fullName: 'nk-sentinel/data-pipeline', language: 'Python', defaultBranch: 'main', lastPush: '2026-03-24T09:00:00Z', private: false, alreadyImported: false },
  { id: 'dr-004', name: 'frontend-app', fullName: 'nk-sentinel/frontend-app', language: 'TypeScript', defaultBranch: 'develop', lastPush: '2026-03-27T08:00:00Z', private: false, alreadyImported: false },
  { id: 'dr-005', name: 'infra-configs', fullName: 'nk-sentinel/infra-configs', language: null, defaultBranch: 'main', lastPush: '2026-03-20T12:00:00Z', private: true, alreadyImported: false },
  { id: 'dr-006', name: 'ml-models', fullName: 'nk-sentinel/ml-models', language: 'Python', defaultBranch: 'main', lastPush: '2026-03-22T16:00:00Z', private: false, alreadyImported: false },
];

/* ---------- Getter functions ---------- */

export function getUserOrgs(): Org[] {
  return MOCK_ORGS;
}

export function getOrgSettings(): OrgSettings {
  return MOCK_ORG_SETTINGS;
}

export function getOrgUsers(): OrgUser[] {
  return MOCK_ORG_USERS;
}

export function getIntegrations(): Integration[] {
  return MOCK_INTEGRATIONS;
}

export function getIntegrationsEnriched(): IntegrationEnriched[] {
  return MOCK_INTEGRATIONS.map((i) => {
    const ageInDays = i.connectedAt
      ? Math.floor((Date.now() - new Date(i.connectedAt).getTime()) / 86400000)
      : null;
    const syncedCounts: Record<string, number> = {
      github: 12,
      gitlab: 5,
      bitbucket: 0,
      jira: 0,
      teams: 0,
    };
    return {
      ...i,
      syncedRepoCount: syncedCounts[i.type] ?? 0,
      tokenAge: ageInDays,
      tokenRotationWarning: ageInDays !== null && ageInDays > 90,
    };
  });
}

export function getDiscoveredRepos(search?: string): DiscoveredRepo[] {
  if (!search) return MOCK_DISCOVERED_REPOS;
  const q = search.toLowerCase();
  return MOCK_DISCOVERED_REPOS.filter(
    (r) => r.name.toLowerCase().includes(q) || r.fullName.toLowerCase().includes(q),
  );
}

export function getAuditLog(): AuditLogEntry[] {
  return MOCK_AUDIT_LOG;
}
