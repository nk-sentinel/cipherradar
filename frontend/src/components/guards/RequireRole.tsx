import { useEffect } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth.tsx';
import type { Role } from '@/lib/roles.ts';

interface RequireRoleProps {
  roles: Role[];
  children: React.ReactNode;
}

/**
 * RBAC guard component. Wraps admin pages and redirects to dashboard
 * with a toast message if the user lacks the required role.
 */
export function RequireRole({ roles, children }: RequireRoleProps): React.ReactElement | null {
  const { user } = useAuth();
  const navigate = useNavigate();

  const hasAccess = user !== null && roles.includes(user.role);

  useEffect(() => {
    if (!hasAccess) {
      void navigate({ to: '/' });
    }
  }, [hasAccess, navigate]);

  if (!hasAccess) {
    return (
      <div
        role="alert"
        style={{
          position: 'fixed',
          top: '16px',
          right: '16px',
          background: 'var(--red)',
          color: '#fff',
          padding: '10px 16px',
          borderRadius: 'var(--radius)',
          fontSize: '12px',
          fontWeight: 600,
          zIndex: 1000,
          boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
        }}
      >
        You do not have permission to access this page.
      </div>
    );
  }

  return <>{children}</>;
}
