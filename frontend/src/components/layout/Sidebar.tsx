import { Link, useRouterState } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth';
import { canAccessPage } from '@/lib/roles';
import { cn } from '@/lib/utils';
import { OrgSwitcher } from './OrgSwitcher.tsx';
import { ProjectTree } from './ProjectTree.tsx';
import { useRequests } from '@/api/hooks/useRequests';
import { useScanQueue } from '@/api/hooks/useScanQueue';
import {
  LayoutDashboard,
  FolderKanban,
  Zap,
  Flag,
  Shield,
  MessageSquare,
  Settings,
  Search,
  GitBranch,
  Award,
  CalendarDays,
  ArrowLeftRight,
  Users,
  Plug,
  ScrollText,
  Package,
  type LucideIcon,
} from 'lucide-react';

interface NavItem {
  label: string;
  icon: LucideIcon;
  to: string;
  page: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Overview',
    items: [
      { label: 'Dashboard', icon: LayoutDashboard, to: '/', page: 'dashboard' },
      { label: 'Projects', icon: FolderKanban, to: '/repos', page: 'repos' },
      { label: 'Scans', icon: Zap, to: '/scans', page: 'repos' },
      { label: 'Findings', icon: Flag, to: '/assets', page: 'assets' },
    ],
  },
  {
    title: 'Portfolio',
    items: [
      { label: 'Compliance', icon: Shield, to: '/compliance', page: 'portfolio-compliance' },
      { label: 'Compliance Dashboard', icon: Award, to: '/compliance-dashboard', page: 'compliance-dashboard' },
      { label: 'Quantum Readiness', icon: Search, to: '/quantum', page: 'portfolio-quantum' },
      { label: 'Dependency Graph', icon: GitBranch, to: '/graph', page: 'graph' },
      { label: 'Certificates', icon: CalendarDays, to: '/certificates', page: 'certificates' },
      { label: 'Cert Tracker', icon: Shield, to: '/certificate-tracker', page: 'certificates' },
      { label: 'CBOM Diff', icon: ArrowLeftRight, to: '/diff', page: 'diff' },
      { label: 'Migration Board', icon: ArrowLeftRight, to: '/migration', page: 'migration' },
    ],
  },
  {
    title: 'Admin',
    items: [
      { label: 'Org Settings', icon: Settings, to: '/admin/settings', page: 'admin-settings' },
      { label: 'Users', icon: Users, to: '/admin/users', page: 'admin-users' },
      { label: 'Integrations', icon: Plug, to: '/admin/integrations', page: 'admin-integrations' },
      { label: 'Audit Log', icon: ScrollText, to: '/admin/audit-log', page: 'admin-audit-log' },
      { label: 'Registries', icon: Package, to: '/admin/registries', page: 'admin-settings' },
    ],
  },
  {
    title: 'Manage',
    items: [
      { label: 'Pending Requests', icon: MessageSquare, to: '/requests', page: 'requests' },
      { label: 'Policy Rules', icon: Shield, to: '/policy', page: 'policy' },
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
  const { data: scanQueueData } = useScanQueue({ status: 'running', perPage: 1 });
  const runningScanCount = scanQueueData?.total ?? 0;

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

      <ProjectTree />

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
              {visibleItems.map((item) => {
                const IconComponent = item.icon;
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className={cn(
                      'nav-item',
                      (item.to === '/'
                        ? currentPath === '/'
                        : currentPath.startsWith(item.to)) &&
                        'active',
                    )}
                  >
                    <span className="nav-icon">
                      <IconComponent size={14} />
                    </span>
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
                    {item.label === 'Scans' && runningScanCount > 0 && (
                      <span
                        className="badge b-blue"
                        style={{ marginLeft: '6px', fontSize: '9px', padding: '1px 5px' }}
                        data-testid="scans-running-badge"
                      >
                        {runningScanCount}
                      </span>
                    )}
                  </Link>
                );
              })}
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
