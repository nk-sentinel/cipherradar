export type Role =
  | 'org-admin'
  | 'security-manager'
  | 'security-engineer'
  | 'team-manager'
  | 'compliance-auditor'
  | 'developer'
  | 'guest';

export const ROLE_LABELS: Record<Role, string> = {
  'org-admin': 'Org Admin',
  'security-manager': 'Security Manager',
  'security-engineer': 'Security Engineer',
  'team-manager': 'Team Manager',
  'compliance-auditor': 'Compliance Auditor',
  developer: 'Developer',
  guest: 'Guest / Viewer',
};

export const ADMIN_ROLES: Role[] = ['org-admin', 'security-manager'];

export const PAGE_ACCESS: Record<Role, string[]> = {
  'org-admin': [
    'dashboard',
    'assets',
    'repos',
    'scans',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'notification-preferences',
    'requests',
    'policy',
    'settings',
    'admin-settings',
    'admin-users',
    'admin-integrations',
    'admin-audit-log',
    'admin-registries',
    'admin-llm-config',
    'runtime',
    'agility-score',
    'hndl-risk',
    'cve-correlation',
  ],
  'security-manager': [
    'dashboard',
    'assets',
    'repos',
    'scans',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'notification-preferences',
    'requests',
    'policy',
    'settings',
    'admin-settings',
    'admin-users',
    'admin-integrations',
    'admin-audit-log',
    'runtime',
    'agility-score',
    'hndl-risk',
    'cve-correlation',
  ],
  'security-engineer': [
    'dashboard',
    'assets',
    'repos',
    'scans',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'notification-preferences',
    'requests',
    'policy',
    'settings',
    'runtime',
    'agility-score',
    'hndl-risk',
    'cve-correlation',
  ],
  'team-manager': [
    'dashboard',
    'assets',
    'repos',
    'scans',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'notification-preferences',
    'requests',
    'runtime',
    'agility-score',
    'hndl-risk',
    'cve-correlation',
  ],
  'compliance-auditor': [
    'dashboard',
    'assets',
    'repos',
    'scans',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'notification-preferences',
    'agility-score',
    'hndl-risk',
    'cve-correlation',
  ],
  developer: ['dashboard', 'assets', 'repos', 'scans', 'graph', 'diff', 'notification-preferences', 'agility-score', 'cve-correlation'],
  guest: ['repos', 'scans'],
};

export function canAccessPage(role: Role, page: string): boolean {
  const pages = PAGE_ACCESS[role];
  return pages.includes(page);
}

export function getDefaultPage(role: Role): string {
  const pages = PAGE_ACCESS[role];
  return pages[0] ?? 'repos';
}
