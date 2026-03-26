import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, fireEvent } from '@testing-library/react';
import { Toaster } from '../../src/components/ui/Toast.tsx';
import { useToast, clearAllToasts } from '../../src/lib/use-toast.ts';

/** Helper component that exposes toast controls for testing. */
function ToastTrigger({
  onMount,
}: {
  onMount: (api: ReturnType<typeof useToast>) => void;
}) {
  const api = useToast();
  onMount(api);
  return null;
}

function renderWithToaster(
  onMount: (api: ReturnType<typeof useToast>) => void,
) {
  return render(
    <>
      <ToastTrigger onMount={onMount} />
      <Toaster />
    </>,
  );
}

describe('Toast system', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    clearAllToasts();
  });

  afterEach(() => {
    clearAllToasts();
    vi.useRealTimers();
  });

  it('shows a toast with title and description', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      api.toast({
        title: 'Saved',
        description: 'Changes persisted',
        variant: 'success',
      });
    });

    expect(screen.getByText('Saved')).toBeInTheDocument();
    expect(screen.getByText('Changes persisted')).toBeInTheDocument();
  });

  it('auto-dismisses success toast after 4 seconds', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      api.toast({ title: 'Done', variant: 'success' });
    });

    expect(screen.getByText('Done')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(4100);
    });

    expect(screen.queryByText('Done')).not.toBeInTheDocument();
  });

  it('auto-dismisses warning toast after 6 seconds', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      api.toast({ title: 'Watch out', variant: 'warning' });
    });

    expect(screen.getByText('Watch out')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(4100);
    });

    // Still visible at 4s
    expect(screen.getByText('Watch out')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(2100);
    });

    expect(screen.queryByText('Watch out')).not.toBeInTheDocument();
  });

  it('error toast persists until manually dismissed', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      api.toast({ title: 'Failed', variant: 'error' });
    });

    // Still there after 10 seconds
    act(() => {
      vi.advanceTimersByTime(10_000);
    });

    expect(screen.getByText('Failed')).toBeInTheDocument();

    // Click dismiss button
    const dismissBtn = screen.getByRole('button', { name: /dismiss/i });
    fireEvent.click(dismissBtn);

    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
  });

  it('limits visible toasts to 5, oldest dismissed when exceeded', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      for (let i = 1; i <= 6; i++) {
        api.toast({ title: `Toast ${String(i)}`, variant: 'info' });
      }
    });

    // The first toast should have been evicted
    expect(screen.queryByText('Toast 1')).not.toBeInTheDocument();
    // Toasts 2-6 should be visible
    expect(screen.getByText('Toast 2')).toBeInTheDocument();
    expect(screen.getByText('Toast 6')).toBeInTheDocument();
  });

  it('programmatic dismiss removes a toast', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    let toastId: string;
    act(() => {
      toastId = api.toast({ title: 'Bye', variant: 'info' });
    });

    expect(screen.getByText('Bye')).toBeInTheDocument();

    act(() => {
      api.dismiss(toastId);
    });

    expect(screen.queryByText('Bye')).not.toBeInTheDocument();
  });

  it('renders correct variant class for each type', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      api.toast({ title: 'S', variant: 'success' });
      api.toast({ title: 'E', variant: 'error' });
      api.toast({ title: 'W', variant: 'warning' });
      api.toast({ title: 'I', variant: 'info' });
    });

    const container = screen.getByText('S').closest('.toast');
    expect(container).toHaveClass('toast-success');

    const errorContainer = screen.getByText('E').closest('.toast');
    expect(errorContainer).toHaveClass('toast-error');

    const warnContainer = screen.getByText('W').closest('.toast');
    expect(warnContainer).toHaveClass('toast-warning');

    const infoContainer = screen.getByText('I').closest('.toast');
    expect(infoContainer).toHaveClass('toast-info');
  });

  it('supports custom duration override', () => {
    let api: ReturnType<typeof useToast>;
    renderWithToaster((a) => {
      api = a;
    });

    act(() => {
      api.toast({ title: 'Custom', variant: 'success', duration: 2000 });
    });

    expect(screen.getByText('Custom')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(2100);
    });

    expect(screen.queryByText('Custom')).not.toBeInTheDocument();
  });

  it('toaster renders in a fixed container', () => {
    renderWithToaster(() => {});
    const container = document.querySelector('.toast-container');
    expect(container).toBeInTheDocument();
  });
});
