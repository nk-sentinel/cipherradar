import { useState, useRef, useEffect, useCallback } from 'react';
import { cn } from '@/lib/utils';

interface Notification {
  id: string;
  message: string;
  time: string;
  unread: boolean;
  severity: 'critical' | 'warning' | 'info' | 'success';
}

const MOCK_NOTIFICATIONS: Notification[] = [
  {
    id: '1',
    message: 'CRITICAL: Certificate validation disabled in payment-service',
    time: '2 minutes ago',
    unread: true,
    severity: 'critical',
  },
  {
    id: '2',
    message: 'Suppression request pending — auth-api SHA-1',
    time: '15 minutes ago',
    unread: true,
    severity: 'warning',
  },
  {
    id: '3',
    message: 'Compliance score dropped: mobile-backend 52% -> 45%',
    time: '1 hour ago',
    unread: true,
    severity: 'warning',
  },
];

const SEVERITY_COLORS: Record<Notification['severity'], string> = {
  critical: 'var(--red)',
  warning: 'var(--orange)',
  info: 'var(--yellow)',
  success: 'var(--green)',
};

export function NotificationBell(): React.ReactElement {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (ref.current && !ref.current.contains(event.target as Node)) {
      setIsOpen(false);
    }
  }, []);

  useEffect(() => {
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [handleClickOutside]);

  const unreadCount = MOCK_NOTIFICATIONS.filter((n) => n.unread).length;

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div
        className="notif-bell"
        onClick={() => setIsOpen((prev) => !prev)}
        role="button"
        tabIndex={0}
        aria-label="Notifications"
      >
        &#128276;
        {unreadCount > 0 && (
          <span className="notif-count">{unreadCount}</span>
        )}
      </div>
      <div className={cn('notif-dropdown', isOpen && 'open')}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '10px 12px',
            borderBottom: '1px solid var(--border)',
            fontSize: '11px',
          }}
        >
          <strong style={{ color: 'var(--text-1)' }}>Notifications</strong>
          <span
            style={{ color: 'var(--accent)', cursor: 'pointer', fontSize: '10px' }}
          >
            Mark all read
          </span>
        </div>
        {MOCK_NOTIFICATIONS.map((notif) => (
          <div
            key={notif.id}
            style={{
              padding: '10px 12px',
              borderBottom: '1px solid var(--border-light)',
              cursor: 'pointer',
              borderLeft: notif.unread
                ? '3px solid var(--accent)'
                : '3px solid transparent',
            }}
          >
            <div style={{ fontSize: '11px', color: 'var(--text-2)' }}>
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  display: 'inline-block',
                  marginRight: '6px',
                  background: SEVERITY_COLORS[notif.severity],
                }}
              />
              {notif.message}
            </div>
            <div
              style={{
                fontSize: '9px',
                color: 'var(--text-4)',
                marginTop: '2px',
              }}
            >
              {notif.time}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
