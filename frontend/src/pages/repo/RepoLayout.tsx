import { Link, Outlet, useNavigate, useParams, useRouterState } from '@tanstack/react-router';
import { useRepository } from '@/api/hooks/useRepositories.ts';
import { cn } from '@/lib/utils.ts';

interface SubTab {
  label: string;
  path: string;
  /** If set, navigates to this external path instead of the repo sub-path */
  externalPath?: (repoId: string) => string;
}

/**
 * Consolidated project tabs (D22 #41).
 * Reduced from 10+ to 6:
 * - Quantum merged into Compliance as a sub-section
 * - SBOM merged into Dependencies
 * - Scan sources, Jira config, notifications, schedule absorbed into Settings
 * - Runtime, Agility Score, HNDL Risk, CVE Correlation folded into existing views
 */
export const CONSOLIDATED_TABS: SubTab[] = [
  { label: 'Overview', path: 'overview' },
  { label: 'Findings', path: 'findings' },
  { label: 'Compliance', path: 'compliance' },
  { label: 'Dependencies', path: 'dependencies' },
  { label: 'Scans', path: 'scans' },
  { label: 'Settings', path: 'settings' },
];

export function RepoLayout(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const { data: repo } = useRepository(repoId);
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  const navigate = useNavigate();

  const repoName = repo?.name ?? repoId;

  return (
    <div>
      <div className="breadcrumb">
        <Link to="/repos">Projects</Link>
        <span>/</span>
        <strong>{repoName}</strong>
      </div>

      <div className="sub-tabs">
        {CONSOLIDATED_TABS.map((tab) => {
          const tabPath = `/repos/${repoId}/${tab.path}`;
          const isActive = currentPath === tabPath;
          const target = tab.externalPath ? tab.externalPath(repoId) : tabPath;
          return (
            <a
              key={tab.path}
              className={cn('sub-tab', isActive && 'active')}
              style={{ cursor: 'pointer', textDecoration: 'none' }}
              onClick={() => void navigate({ to: target })}
            >
              {tab.label}
            </a>
          );
        })}
      </div>

      <Outlet />
    </div>
  );
}
