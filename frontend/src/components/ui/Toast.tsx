import { useToast } from '@/lib/use-toast.ts';
import type { ToastData, ToastVariant } from '@/lib/use-toast.ts';
import { cn } from '@/lib/utils.ts';

// ---------------------------------------------------------------------------
// Variant icon map (plain text icons — no icon library dependency)
// ---------------------------------------------------------------------------

const VARIANT_ICON: Record<ToastVariant, string> = {
  success: '\u2713', // checkmark
  error: '\u2717',   // ballot x
  warning: '\u26A0', // warning sign
  info: '\u2139',    // info
};

// ---------------------------------------------------------------------------
// Single toast
// ---------------------------------------------------------------------------

interface ToastItemProps {
  data: ToastData;
  onDismiss: (id: string) => void;
}

function ToastItem({ data, onDismiss }: ToastItemProps): React.ReactElement {
  return (
    <div
      className={cn('toast', `toast-${data.variant}`)}
      role="status"
      aria-live="polite"
    >
      <span className="toast-icon">{VARIANT_ICON[data.variant]}</span>
      <div className="toast-body">
        <div className="toast-title">{data.title}</div>
        {data.description ? (
          <div className="toast-desc">{data.description}</div>
        ) : null}
      </div>
      <button
        className="toast-dismiss"
        onClick={() => onDismiss(data.id)}
        aria-label="Dismiss"
        type="button"
      >
        \u00D7
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Toaster — renders all active toasts
// ---------------------------------------------------------------------------

export function Toaster(): React.ReactElement {
  const { toasts, dismiss } = useToast();

  return (
    <div className="toast-container" aria-label="Notifications">
      {toasts.map((t) => (
        <ToastItem key={t.id} data={t} onDismiss={dismiss} />
      ))}
    </div>
  );
}
