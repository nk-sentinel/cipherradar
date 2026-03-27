import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { Server } from 'mock-socket';
import { useState, useEffect } from 'react';
import { ScanProgressBar } from '../../src/components/scan/ScanProgressBar';
import { useScanProgress } from '../../src/lib/use-scan-progress';

/* ---------------------------------------------------------------------------
 * Direct ScanProgressBar tests (pure component, no WebSocket)
 * -------------------------------------------------------------------------- */

describe('ScanProgressBar', () => {
  it('shows the stage label', () => {
    render(
      <ScanProgressBar
        status="cloning"
        progressPct={10}
        isComplete={false}
        isError={false}
      />,
    );

    expect(screen.getByTestId('scan-progress-stage')).toHaveTextContent('Cloning');
    expect(screen.getByTestId('scan-progress-pct')).toHaveTextContent('10%');
  });

  it('turns green on complete', () => {
    render(
      <ScanProgressBar
        status="completed"
        progressPct={100}
        isComplete={true}
        isError={false}
      />,
    );

    const stage = screen.getByTestId('scan-progress-stage');
    expect(stage).toHaveTextContent('Complete');
    expect(stage).toHaveStyle({ color: 'var(--green)' });

    const fill = screen.getByTestId('scan-progress-fill');
    expect(fill).toHaveStyle({ background: 'var(--green)' });
  });

  it('turns red on failure', () => {
    render(
      <ScanProgressBar
        status="failed"
        progressPct={0}
        isComplete={false}
        isError={true}
      />,
    );

    const stage = screen.getByTestId('scan-progress-stage');
    expect(stage).toHaveTextContent('Failed');
    expect(stage).toHaveStyle({ color: 'var(--red)' });

    const fill = screen.getByTestId('scan-progress-fill');
    expect(fill).toHaveStyle({ background: 'var(--red)' });
  });

  it('shows detail text when provided', () => {
    render(
      <ScanProgressBar
        status="scanning_pass1"
        progressPct={30}
        detail="Processing 42 files..."
        isComplete={false}
        isError={false}
      />,
    );

    expect(screen.getByTestId('scan-progress-detail')).toHaveTextContent('Processing 42 files...');
  });
});

/* ---------------------------------------------------------------------------
 * WebSocket integration test with mock-socket
 * -------------------------------------------------------------------------- */

describe('useScanProgress with mock-socket', () => {
  let mockServer: Server | null = null;

  afterEach(() => {
    if (mockServer) {
      mockServer.close();
      mockServer = null;
    }
  });

  function TestHarness({ scanId }: { scanId: string }) {
    const progress = useScanProgress(scanId);
    return (
      <ScanProgressBar
        status={progress.status}
        progressPct={progress.progressPct}
        detail={progress.detail}
        isComplete={progress.isComplete}
        isError={progress.isError}
      />
    );
  }

  it.skip('receives progress via WebSocket', async () => {
    // TODO: mock-socket URL must match hook's constructed URL — test via E2E instead
    const fakeURL = 'ws://localhost/api/v1/ws/scans/test-ws-123';
    mockServer = new Server(fakeURL);

    mockServer.on('connection', (socket) => {
      socket.send(JSON.stringify({ status: 'cloning', progress_pct: 10, detail: 'Cloning repo...' }));
    });

    await act(async () => {
      render(<TestHarness scanId="test-ws-123" />);
    });

    // Allow WebSocket message to propagate
    await act(async () => {
      await new Promise((r) => setTimeout(r, 100));
    });

    expect(screen.getByTestId('scan-progress-stage')).toHaveTextContent('Cloning');
  });
});
