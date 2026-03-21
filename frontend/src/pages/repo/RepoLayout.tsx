import { Link, Outlet, useNavigate, useParams, useRouterState } from '@tanstack/react-router';
import { useRepository } from '@/api/hooks/useRepositories.ts';
import { cn } from '@/lib/utils.ts';

interface SubTab {
  label: string;
  path: string;
  /** If set, navigates to this external path instead of the repo sub-path */
  externalPath?: (repoId: string) => string;
}

const SUB_TABS: SubTab[] = [
  { label: 'Overview', path: 'overview' },
  { label: 'Scans', path: 'scans' },
  { label: 'Findings', path: 'findings' },
  { label: 'CBOM Diff', path: 'diff' },
  { label: 'Quantum', path: 'quantum' },
  { label: 'Compliance', path: 'compliance' },
  { label: 'Runtime', path: 'runtime' },
  { label: 'Agility Score', path: 'agility' },
  { label: 'HNDL Risk', path: 'hndl-risk' },
  { label: 'CVE Correlation', path: 'cve-correlation' },
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
        <Link to="/repos">Repositories</Link>
        <span>/</span>
        <strong>{repoName}</strong>
      </div>

      <div className="sub-tabs">
        {SUB_TABS.map((tab) => {
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
