import { useSyncExternalStore, useCallback } from 'react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

export interface ToastData {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
  duration?: number;
}

export interface ToastInput {
  title: string;
  description?: string;
  variant: ToastVariant;
  /** Override auto-dismiss duration in ms. Ignored for error toasts (which persist). */
  duration?: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOASTS = 5;

const DEFAULT_DURATION: Record<ToastVariant, number | null> = {
  success: 4000,
  error: null, // persists until manually dismissed
  warning: 6000,
  info: 4000,
};

// ---------------------------------------------------------------------------
// External store — shared across all useToast() consumers
// ---------------------------------------------------------------------------

let toasts: ToastData[] = [];
let nextId = 0;
const listeners = new Set<() => void>();
const timers = new Map<string, ReturnType<typeof setTimeout>>();

function emitChange(): void {
  for (const listener of listeners) {
    listener();
  }
}

function getSnapshot(): ToastData[] {
  return toasts;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function addToast(input: ToastInput): string {
  const id = String(++nextId);
  const toast: ToastData = { id, ...input };

  toasts = [...toasts, toast];

  // Enforce max visible limit — remove oldest when exceeded
  if (toasts.length > MAX_TOASTS) {
    const evicted = toasts[0];
    if (evicted) {
      clearScheduledDismiss(evicted.id);
    }
    toasts = toasts.slice(toasts.length - MAX_TOASTS);
  }

  // Schedule auto-dismiss
  const variant = input.variant;
  const duration =
    input.duration !== undefined ? input.duration : DEFAULT_DURATION[variant];

  if (duration !== null) {
    const timer = setTimeout(() => {
      removeToast(id);
    }, duration);
    timers.set(id, timer);
  }

  emitChange();
  return id;
}

function removeToast(id: string): void {
  clearScheduledDismiss(id);
  toasts = toasts.filter((t) => t.id !== id);
  emitChange();
}

function clearScheduledDismiss(id: string): void {
  const timer = timers.get(id);
  if (timer !== undefined) {
    clearTimeout(timer);
    timers.delete(id);
  }
}

/** Remove all toasts and cancel pending timers. Useful for testing. */
export function clearAllToasts(): void {
  for (const timer of timers.values()) {
    clearTimeout(timer);
  }
  timers.clear();
  toasts = [];
  emitChange();
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useToast(): {
  toast: (input: ToastInput) => string;
  dismiss: (id: string) => void;
  toasts: ToastData[];
} {
  const currentToasts = useSyncExternalStore(subscribe, getSnapshot);

  const toast = useCallback((input: ToastInput): string => {
    return addToast(input);
  }, []);

  const dismiss = useCallback((id: string): void => {
    removeToast(id);
  }, []);

  return { toast, dismiss, toasts: currentToasts };
}
