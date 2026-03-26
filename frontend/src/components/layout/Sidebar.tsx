import { Link, useRouterState } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth';
import { canAccessPage } from '@/lib/roles';
import { cn } from '@/lib/utils';
import { OrgSwitcher } from './OrgSwitcher.tsx';
import { useRequests } from '@/api/hooks/useRequests';

interface NavItem {
  label: string;
  icon: string;
  to: string;
  page: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Overview',
    items: [
      { label: 'Dashboard', icon: '\u25A0', to: '/', page: 'dashboard' },
      { label: 'Asset Explorer', icon: '\u26B1', to: '/assets', page: 'assets' },
      { label: 'Repositories', icon: '\u2630', to: '/repos', page: 'repos' },
    ],
  },
  {
    title: 'Portfolio',
    items: [
      { label: 'Quantum Readiness', icon: '\u269B', to: '/quantum', page: 'portfolio-quantum' },
      { label: 'Compliance', icon: '\u2713', to: '/compliance', page: 'portfolio-compliance' },
      { label: 'Compliance Dashboard', icon: '\u2611', to: '/compliance-dashboard', page: 'compliance-dashboard' },
      { label: 'Dependency Graph', icon: '\u2B21', to: '/graph', page: 'graph' },
      { label: 'Certificates', icon: '\u2B50', to: '/certificates', page: 'certificates' },
      { label: 'CBOM Diff', icon: '\u0394', to: '/diff', page: 'diff' },
      { label: 'Migration Board', icon: '\u21C4', to: '/migration', page: 'migration' },
    ],
  },
  {
    title: 'Admin',
    items: [
      { label: 'Org Settings', icon: '\u2699', to: '/admin/settings', page: 'admin-settings' },
      { label: 'Users', icon: '\u263A', to: '/admin/users', page: 'admin-users' },
      { label: 'Integrations', icon: '\u26A1', to: '/admin/integrations', page: 'admin-integrations' },
      { label: 'Audit Log', icon: '\u2637', to: '/admin/audit-log', page: 'admin-audit-log' },
    ],
  },
  {
    title: 'Manage',
    items: [
      { label: 'Pending Requests', icon: '\u2709', to: '/requests', page: 'requests' },
      { label: 'Policy Rules', icon: '\u2699', to: '/policy', page: 'policy' },
    ],
  },
];

export function Sidebar(): React.ReactElement {
  const { user } = useAuth();
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  const role = user?.role ?? 'guest';
  const canSeeRequests = canAccessPage(role, 'requests');
  const { data: requestsData } = useRequests(1, 1);
  const pendingCount = canSeeRequests ? (requestsData?.total ?? 0) : 0;

  return (
    <nav className="sidebar">
      <div className="logo">
        <svg viewBox="0 0 32 32" fill="none" width="28" height="28">
          <path
            d="M16 2L28 9V23L16 30L4 23V9L16 2Z"
            stroke="currentColor"
            strokeWidth="1.5"
            style={{ color: 'var(--accent)' }}
          />
          <circle
            cx="16"
            cy="16"
            r="4"
            fill="currentColor"
            style={{ color: 'var(--accent)' }}
          />
        </svg>
        <div>
          <span className="logo-text">CipherRadar</span>
          <span className="logo-sub">CBOM Platform</span>
        </div>
      </div>

      <OrgSwitcher />

      <div>
        {NAV_SECTIONS.map((section) => {
          const visibleItems = section.items.filter((item) =>
            canAccessPage(role, item.page),
          );

          if (visibleItems.length === 0) {
            return null;
          }

          return (
            <div key={section.title}>
              <div className="nav-section">{section.title}</div>
              {visibleItems.map((item) => (
                <Link
                  key={item.page}
                  to={item.to}
                  className={cn(
                    'nav-item',
                    (item.to === '/'
                      ? currentPath === '/'
                      : currentPath.startsWith(item.to)) &&
                      'active',
                  )}
                >
                  <span className="nav-icon">{item.icon}</span>
                  {item.label}
                  {item.page === 'requests' && pendingCount > 0 && (
                    <span
                      className="badge b-crit"
                      style={{ marginLeft: '6px', fontSize: '9px', padding: '1px 5px' }}
                      data-testid="requests-count-badge"
                    >
                      {pendingCount}
                    </span>
                  )}
                </Link>
              ))}
            </div>
          );
        })}
      </div>

      <div style={{ flex: 1 }} />
      <div className="sidebar-footer">
        nk-sentinel &middot; Enterprise
      </div>
    </nav>
  );
}
