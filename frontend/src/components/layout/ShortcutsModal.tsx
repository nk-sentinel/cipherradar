import { useEffect, useRef, useCallback } from 'react';

export interface ShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export interface ShortcutEntry {
  keys: string;
  action: string;
}

export const SHORTCUTS: ShortcutEntry[] = [
  { keys: 'Ctrl+K', action: 'Search' },
  { keys: 'Ctrl+B', action: 'Toggle sidebar' },
  { keys: '?', action: 'Show this modal' },
  { keys: 'Esc', action: 'Close modal / dropdown' },
  { keys: 'g d', action: 'Go to Dashboard' },
  { keys: 'g r', action: 'Go to Repositories' },
  { keys: 'g q', action: 'Go to Quantum Readiness' },
];

export function ShortcutsModal({ isOpen, onClose }: ShortcutsModalProps): React.ReactElement | null {
  const overlayRef = useRef<HTMLDivElement>(null);
  const modalRef = useRef<HTMLDivElement>(null);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      // Focus trap: cycle focus within the modal on Tab
      if (e.key === 'Tab') {
        const focusable = modalRef.current?.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (!focusable?.length) return;
        const first = focusable[0] as HTMLElement | undefined;
        const last = focusable[focusable.length - 1] as HTMLElement | undefined;
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    },
    [onClose],
  );

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      // Focus trap: focus the modal when it opens
      modalRef.current?.focus();
    }
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  return (
    <div
      ref={overlayRef}
      data-testid="shortcuts-modal-overlay"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={modalRef}
        className="card"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        tabIndex={-1}
        data-testid="shortcuts-modal"
        style={{
          width: '460px',
          maxHeight: '80vh',
          overflow: 'auto',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '16px',
          }}
        >
          <div className="card-title" style={{ marginBottom: 0 }}>
            Keyboard Shortcuts
          </div>
          <button
            onClick={onClose}
            aria-label="Close shortcuts modal"
            data-testid="shortcuts-modal-close"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-3)',
              cursor: 'pointer',
              fontSize: '18px',
              lineHeight: 1,
              padding: '0 4px',
            }}
          >
            {'\u2715'}
          </button>
        </div>

        <table data-testid="shortcuts-table">
          <thead>
            <tr>
              <th scope="col">Shortcut</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {SHORTCUTS.map((shortcut) => (
              <tr key={shortcut.keys}>
                <td>
                  <kbd
                    style={{
                      display: 'inline-block',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius)',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-0)',
                      fontSize: '11px',
                      fontFamily: 'var(--font, monospace)',
                      color: 'var(--text-1)',
                    }}
                  >
                    {shortcut.keys}
                  </kbd>
                </td>
                <td style={{ color: 'var(--text-2)' }}>{shortcut.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
