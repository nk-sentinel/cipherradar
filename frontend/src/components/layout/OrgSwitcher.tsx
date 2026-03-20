import { useState, useRef, useEffect } from 'react';
import { useUserOrgs } from '@/api/hooks/useOrgs.ts';
import { useCurrentOrg } from '@/lib/org-context.tsx';

export function OrgSwitcher(): React.ReactElement {
  const { data: orgs } = useUserOrgs();
  const { currentOrg, setCurrentOrg } = useCurrentOrg();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  if (!orgs || orgs.length <= 1) {
    // Single org — show static label, no dropdown
    return (
      <div className="org-switcher" style={{ padding: '6px 16px 10px', marginBottom: '4px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '11px',
            color: 'var(--text-2)',
          }}
        >
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '2px',
              background: 'var(--accent)',
              flexShrink: 0,
            }}
          />
          {currentOrg?.name ?? 'Organization'}
        </div>
      </div>
    );
  }

  return (
    <div
      ref={ref}
      className="org-switcher"
      style={{ padding: '6px 16px 10px', marginBottom: '4px', position: 'relative' }}
    >
      <button
        onClick={() => setOpen(!open)}
        aria-label="Switch organization"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          width: '100%',
          background: open ? 'var(--bg-3)' : 'transparent',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          padding: '6px 8px',
          cursor: 'pointer',
          color: 'var(--text-2)',
          fontSize: '11px',
          fontFamily: 'inherit',
          transition: 'background 0.12s',
        }}
      >
        <span
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '2px',
            background: 'var(--accent)',
            flexShrink: 0,
          }}
        />
        <span style={{ flex: 1, textAlign: 'left', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {currentOrg?.name ?? 'Select Org'}
        </span>
        <span style={{ fontSize: '8px', color: 'var(--text-4)' }}>
          {open ? '\u25B2' : '\u25BC'}
        </span>
      </button>

      {open && (
        <div
          role="listbox"
          aria-label="Organization list"
          style={{
            position: 'absolute',
            top: '100%',
            left: '16px',
            right: '16px',
            background: 'var(--bg-1)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            zIndex: 50,
            boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
            overflow: 'hidden',
          }}
        >
          {orgs.map((org) => (
            <div
              key={org.id}
              role="option"
              aria-selected={currentOrg?.id === org.id}
              onClick={() => {
                setCurrentOrg(org);
                setOpen(false);
              }}
              style={{
                padding: '8px 10px',
                fontSize: '11px',
                cursor: 'pointer',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                color: currentOrg?.id === org.id ? 'var(--accent)' : 'var(--text-2)',
                background: currentOrg?.id === org.id ? 'var(--accent-dim)' : 'transparent',
              }}
            >
              <span>{org.name}</span>
              <span
                style={{
                  fontSize: '9px',
                  padding: '1px 5px',
                  borderRadius: 'var(--radius)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-4)',
                }}
              >
                {org.plan}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
