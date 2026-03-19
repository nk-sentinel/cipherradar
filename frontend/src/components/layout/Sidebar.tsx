import { Link, useRouterState } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth';
import { canAccessPage } from '@/lib/roles';
import { cn } from '@/lib/utils';

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
      { label: 'Repositories', icon: '\u2630', to: '/repos', page: 'repos' },
    ],
  },
  {
    title: 'Portfolio',
    items: [
      { label: 'Quantum Readiness', icon: '\u269B', to: '/', page: 'portfolio-quantum' },
      { label: 'Compliance', icon: '\u2713', to: '/', page: 'portfolio-compliance' },
    ],
  },
  {
    title: 'Manage',
    items: [
      { label: 'Policy Rules', icon: '\u2699', to: '/', page: 'policy' },
      { label: 'Settings', icon: '\u2699', to: '/', page: 'settings' },
    ],
  },
];

export function Sidebar(): React.ReactElement {
  const { user } = useAuth();
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  const role = user?.role ?? 'guest';

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
                    (item.page === 'dashboard'
                      ? currentPath === item.to
                      : currentPath.startsWith(item.to) && item.to !== '/') &&
                      'active',
                  )}
                >
                  <span className="nav-icon">{item.icon}</span>
                  {item.label}
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
