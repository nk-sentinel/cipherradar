import { Link, useRouterState, useParams } from '@tanstack/react-router';
import { useRepository } from '@/api/hooks/useRepositories';
import { useOptionalCurrentOrg } from '@/lib/org-context';

export interface BreadcrumbSegment {
  label: string;
  to: string;
}

/** Map of path segments to human-readable labels */
const PATH_LABELS: Record<string, string> = {
  repos: 'Projects',
  assets: 'Findings',
  quantum: 'Quantum Readiness',
  compliance: 'Portfolio Compliance',
  graph: 'Dependency Graph',
  'certificate-tracker': 'Certificate Tracker',
  diff: 'CBOM Diff',
  policy: 'Policy Rules',
  requests: 'Pending Requests',
  scans: 'Scans',
  admin: 'Admin',
  settings: 'Settings',
  users: 'Users',
  integrations: 'Integrations',
  'audit-log': 'Audit Log',
  registries: 'Registries',
  profile: 'Profile',
  downloads: 'Downloads',
  overview: 'Overview',
  findings: 'Findings',
  dependencies: 'Dependencies',
  'compliance-dashboard': 'Compliance Dashboard',
  'llm-config': 'AI Remediation',
  'hndl-risk': 'HNDL Risk',
  agility: 'Agility Score',
  runtime: 'Runtime',
  'cve-correlation': 'CVE Correlation',
};

interface BuildContext {
  repoId?: string;
  repoName?: string;
  orgName?: string;
  groupName?: string;
}

/**
 * Build breadcrumb segments from a pathname.
 * Returns an array of { label, to } objects.
 *
 * 4-level breadcrumb: Org > Group > Project > Tab
 */
export function buildBreadcrumbs(pathname: string, context: BuildContext): BreadcrumbSegment[] {
  const segments: BreadcrumbSegment[] = [];

  // Level 1: Org name as the root breadcrumb when available
  if (context.orgName) {
    segments.push({
      label: context.orgName,
      to: '/',
    });
  }

  // Dashboard (root) — show "Org Name > Dashboard"
  if (pathname === '/') {
    segments.push({ label: 'Dashboard', to: '/' });
    return segments;
  }

  const parts = pathname.split('/').filter(Boolean);

  // Handle /repos/:repoId/... pattern
  if (parts[0] === 'repos' && parts.length >= 2 && context.repoId) {
    // Level 2: Group breadcrumb (if available)
    if (context.groupName) {
      segments.push({
        label: context.groupName,
        to: '/repos',
      });
    }

    // Level 3: Project/repo breadcrumb
    segments.push({
      label: context.repoName ?? context.repoId,
      to: `/repos/${context.repoId}/overview`,
    });

    // Level 4: Tab breadcrumb (if present)
    if (parts.length >= 3) {
      const tab = parts[2] ?? '';
      const label = PATH_LABELS[tab] ?? tab;
      segments.push({
        label,
        to: `/repos/${context.repoId}/${tab}`,
      });
    }

    return segments;
  }

  // Handle /admin/... pattern
  if (parts[0] === 'admin') {
    segments.push({
      label: 'Admin',
      to: '/admin/settings',
    });
    if (parts.length >= 2) {
      const subPage = parts[1] ?? '';
      const label = PATH_LABELS[subPage] ?? subPage;
      segments.push({
        label,
        to: `/admin/${subPage}`,
      });
    }
    return segments;
  }

  // Generic path — prepend page segments after org name
  let builtPath = '';
  for (const part of parts) {
    builtPath += `/${part}`;
    const label = PATH_LABELS[part] ?? part;
    segments.push({
      label,
      to: builtPath,
    });
  }

  return segments;
}

/**
 * Extract group name from a repository's orgPath.
 * E.g. "nk-sentinel/payment-service" => "nk-sentinel"
 */
function extractGroupName(orgPath?: string): string | undefined {
  if (!orgPath) return undefined;
  const parts = orgPath.split('/');
  return parts.length >= 2 ? parts[0] : undefined;
}

/**
 * Hook that derives breadcrumb segments from the current route.
 */
export function useBreadcrumbs(): BreadcrumbSegment[] {
  const routerState = useRouterState();
  const pathname = routerState.location.pathname;
  const params = useParams({ strict: false }) as { repoId?: string };

  // C1 fix: use useOptionalCurrentOrg unconditionally (no try/catch around hooks)
  const orgCtx = useOptionalCurrentOrg();
  const orgName = orgCtx?.currentOrg?.name ?? undefined;

  const repoId = params.repoId;
  const { data: repo } = useRepository(repoId ?? '');
  const repoName = repoId ? repo?.name : undefined;
  const groupName = repoId ? extractGroupName(repo?.orgPath) : undefined;

  return buildBreadcrumbs(pathname, {
    repoId,
    repoName,
    orgName,
    groupName,
  });
}

/**
 * Breadcrumbs navigation component.
 * Shows: Org > Group > Project > Tab
 * Each segment is clickable.
 */
export function Breadcrumbs(): React.ReactElement {
  const segments = useBreadcrumbs();

  if (segments.length === 0) {
    return <div data-testid="breadcrumbs" />;
  }

  return (
    <nav
      data-testid="breadcrumbs"
      aria-label="Breadcrumbs"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        fontSize: '12px',
        color: 'var(--text-3)',
      }}
    >
      {segments.map((segment, index) => {
        const isLast = index === segments.length - 1;
        return (
          <span key={segment.to} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            {index > 0 && (
              <span style={{ color: 'var(--text-4)', fontSize: '10px' }}>/</span>
            )}
            {isLast ? (
              <span style={{ color: 'var(--text-1)', fontWeight: 500 }}>
                {segment.label}
              </span>
            ) : (
              <Link
                to={segment.to}
                style={{
                  color: 'var(--text-3)',
                  textDecoration: 'none',
                }}
              >
                {segment.label}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
