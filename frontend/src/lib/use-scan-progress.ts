import { useState, useEffect, useRef } from 'react';

export interface ScanProgress {
  status: string;
  progressPct: number;
  detail: string;
  isComplete: boolean;
  isError: boolean;
}

const INITIAL_PROGRESS: ScanProgress = {
  status: 'queued',
  progressPct: 0,
  detail: '',
  isComplete: false,
  isError: false,
};

export function useScanProgress(scanId: string | null): ScanProgress {
  const [progress, setProgress] = useState<ScanProgress>(INITIAL_PROGRESS);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId) {
      setProgress(INITIAL_PROGRESS);
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws/scans/${scanId}`);
    wsRef.current = ws;

    ws.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data as string) as {
          status: string;
          progress_pct: number;
          detail?: string;
        };
        setProgress({
          status: data.status,
          progressPct: data.progress_pct,
          detail: data.detail ?? '',
          isComplete: data.status === 'completed',
          isError: data.status === 'failed',
        });
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onerror = () => {
      setProgress((prev) => ({ ...prev, isError: true, status: 'failed' }));
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [scanId]);

  return progress;
}
