import { useEffect } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth.tsx';
import type { Role } from '@/lib/roles.ts';

interface RequireRoleProps {
  roles: Role[];
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

/**
 * RBAC guard component. Wraps admin pages and redirects to dashboard
 * with a toast message if the user lacks the required role.
 */
export function RequireRole({ roles, children, fallback }: RequireRoleProps): React.ReactElement | null {
  const { user } = useAuth();
  const navigate = useNavigate();

  const hasAccess = user !== null && roles.includes(user.role);

  useEffect(() => {
    if (!hasAccess && !fallback) {
      void navigate({ to: '/' });
    }
  }, [hasAccess, fallback, navigate]);

  if (!hasAccess) {
    if (fallback) {
      return <>{fallback}</>;
    }
    return (
      <div className="card" role="alert" style={{ marginTop: '20px' }}>
        <p style={{ color: 'var(--red)', fontSize: '13px', fontWeight: 600 }}>
          Access Denied
        </p>
        <p style={{ color: 'var(--text-2)', fontSize: '12px', marginTop: '4px' }}>
          You do not have permission to access this page. Contact your administrator for access.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
