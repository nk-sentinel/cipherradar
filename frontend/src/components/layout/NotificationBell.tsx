import { useState, useRef, useEffect, useCallback } from 'react';
import { cn } from '@/lib/utils';
import {
  useNotifications,
  useMarkRead,
  useMarkAllRead,
} from '@/api/hooks/useNotifications.ts';
import type { NotificationSeverity } from '@/mocks/data/notifications.ts';

const SEVERITY_COLORS: Record<NotificationSeverity, string> = {
  critical: 'var(--red)',
  warning: 'var(--orange)',
  info: 'var(--yellow)',
  success: 'var(--green)',
};

export function NotificationBell(): React.ReactElement {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const { data: notifications = [] } = useNotifications();
  const markRead = useMarkRead();
  const markAllRead = useMarkAllRead();

  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (ref.current && !ref.current.contains(event.target as Node)) {
      setIsOpen(false);
    }
  }, []);

  useEffect(() => {
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [handleClickOutside]);

  const unreadCount = notifications.filter((n) => n.unread).length;

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
            role="button"
            tabIndex={0}
            onClick={() => markAllRead.mutate()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                markAllRead.mutate();
              }
            }}
          >
            Mark all read
          </span>
        </div>
        {notifications.length === 0 && (
          <div style={{ padding: '16px 12px', fontSize: '11px', color: 'var(--text-3)' }}>
            No notifications
          </div>
        )}
        {notifications.map((notif) => (
          <div
            key={notif.id}
            onClick={() => {
              if (notif.unread) {
                markRead.mutate(notif.id);
              }
            }}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                if (notif.unread) {
                  markRead.mutate(notif.id);
                }
              }
            }}
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
