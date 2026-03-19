import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth';
import { ROLE_LABELS } from '@/lib/roles';
import { cn } from '@/lib/utils';

export function AvatarDropdown(): React.ReactElement {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (ref.current && !ref.current.contains(event.target as Node)) {
      setIsOpen(false);
    }
  }, []);

  useEffect(() => {
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [handleClickOutside]);

  const handleSignOut = (): void => {
    logout();
    setIsOpen(false);
    void navigate({ to: '/login' });
  };

  const initials = user?.initials ?? '??';
  const name = user?.name ?? 'Unknown';
  const email = user?.email ?? '';
  const roleLabel = user ? ROLE_LABELS[user.role] : '';

  return (
    <div ref={ref} className="avatar-area">
      <div
        className="avatar-btn"
        onClick={() => setIsOpen((prev) => !prev)}
        role="button"
        tabIndex={0}
      >
        <div className="avatar-circle">{initials}</div>
        <div className="avatar-info">
          <div className="avatar-name">{name}</div>
          <div className="avatar-role">{roleLabel}</div>
        </div>
        <span className="avatar-chevron">&#9662;</span>
      </div>

      <div className={cn('avatar-dropdown', isOpen && 'open')}>
        <div className="avatar-dropdown-header">
          <div className="name">{name}</div>
          <div className="email">{email}</div>
        </div>
        <div
          className="avatar-dropdown-item"
          onClick={() => { setIsOpen(false); void navigate({ to: '/profile' as string }); }}
          role="button"
          tabIndex={0}
        >
          <span className="dd-icon">&#9786;</span> My Profile
        </div>
        <div
          className="avatar-dropdown-item"
          onClick={() => { setIsOpen(false); void navigate({ to: '/downloads' as string }); }}
          role="button"
          tabIndex={0}
        >
          <span className="dd-icon">&#8615;</span> CLI Downloads
        </div>
        <div className="avatar-dropdown-divider" />
        <div
          className="avatar-dropdown-item"
          onClick={() => setIsOpen(false)}
          role="button"
          tabIndex={0}
        >
          <span className="dd-icon">&#128196;</span> API Documentation
        </div>
        <div
          className="avatar-dropdown-item"
          onClick={() => setIsOpen(false)}
          role="button"
          tabIndex={0}
        >
          <span className="dd-icon">&#9881;</span> Keyboard Shortcuts
        </div>
        <div
          className="avatar-dropdown-item"
          onClick={() => setIsOpen(false)}
          role="button"
          tabIndex={0}
        >
          <span className="dd-icon">&#10067;</span> Help & Docs
        </div>
        <div className="avatar-dropdown-divider" />
        <div
          className="avatar-dropdown-item danger"
          onClick={handleSignOut}
          role="button"
          tabIndex={0}
        >
          <span className="dd-icon">&#8617;</span> Sign Out
        </div>
      </div>
    </div>
  );
}
