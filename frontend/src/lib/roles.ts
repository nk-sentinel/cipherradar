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

export const PAGE_ACCESS: Record<Role, string[]> = {
  'org-admin': [
    'dashboard',
    'assets',
    'repos',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'policy',
    'settings',
  ],
  'security-manager': [
    'dashboard',
    'assets',
    'repos',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'policy',
    'settings',
  ],
  'security-engineer': [
    'dashboard',
    'assets',
    'repos',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
    'policy',
    'settings',
  ],
  'team-manager': [
    'dashboard',
    'assets',
    'repos',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
  ],
  'compliance-auditor': [
    'dashboard',
    'assets',
    'repos',
    'portfolio-quantum',
    'portfolio-compliance',
    'compliance-dashboard',
    'graph',
    'certificates',
    'diff',
  ],
  developer: ['dashboard', 'assets', 'repos', 'graph', 'diff'],
  guest: ['repos'],
};

export function canAccessPage(role: Role, page: string): boolean {
  const pages = PAGE_ACCESS[role];
  return pages.includes(page);
}

export function getDefaultPage(role: Role): string {
  const pages = PAGE_ACCESS[role];
  return pages[0] ?? 'repos';
}
