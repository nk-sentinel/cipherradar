import { redirect } from '@tanstack/react-router';
import { canAccessPage, getDefaultPage } from './roles';
import type { Role } from './roles';

/** Maps PAGE_ACCESS page names to route paths for redirect fallback. */
const PAGE_TO_ROUTE: Record<string, string> = {
  dashboard: '/',
  assets: '/assets',
  repos: '/repos',
  'portfolio-quantum': '/quantum',
  'portfolio-compliance': '/compliance',
  'compliance-dashboard': '/compliance-dashboard',
  graph: '/graph',
  certificates: '/certificate-tracker',
  diff: '/diff',
  'notification-preferences': '/notifications/preferences',
  requests: '/requests',
  scans: '/scans',
  policy: '/policy',
  'admin-settings': '/admin/settings',
  'admin-users': '/admin/users',
  'admin-integrations': '/admin/integrations',
  'admin-audit-log': '/admin/audit-log',
};

/**
 * Creates a TanStack Router `beforeLoad` guard that checks the
 * current user's role against PAGE_ACCESS for the given page name.
 *
 * - If no user session exists, redirects to /login.
 * - If the user's role lacks access, redirects to their default page
 *   (avoiding infinite redirect when the default page itself is denied).
 */
export function createRouteGuard(pageName: string) {
  return () => {
    const userJson = sessionStorage.getItem('cipherradar-user');
    if (!userJson) {
      throw redirect({ to: '/login' });
    }
    const user = JSON.parse(userJson) as { role?: string };
    const role = (user.role ?? 'guest') as Role;
    if (!canAccessPage(role, pageName)) {
      const defaultPage = getDefaultPage(role);
      const fallbackRoute = PAGE_TO_ROUTE[defaultPage] ?? '/repos';
      throw redirect({ to: fallbackRoute });
    }
  };
}
