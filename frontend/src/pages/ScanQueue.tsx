import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useScanQueue, type ScanQueueItem } from '@/api/hooks/useScanQueue';
import { useRepositories } from '@/api/hooks/useRepositories';
import { apiClient } from '@/api/client';
import { Pagination } from '@/components/ui/Pagination';
import { EmptyState } from '@/components/ui/EmptyState';
import { AccessibleTable } from '@/components/ui/AccessibleTable';
import { EnvironmentBadge } from '@/components/scan/EnvironmentBadge';
import { PromoteModal } from '@/components/scan/PromoteModal';


const STATUS_OPTIONS = ['', 'queued', 'running', 'completed', 'failed', 'cancelled'];
const TRIGGER_OPTIONS = ['', 'manual', 'schedule', 'webhook', 'push'];

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'queued': return 'badge b-amber';
    case 'running': return 'badge b-blue';
    case 'completed': return 'badge b-safe';
    case 'failed': return 'badge b-crit';
    case 'cancelled': return 'badge b-gray';
    default: return 'badge';
  }
}

function triggerBadgeClass(trigger: string): string {
  switch (trigger) {
    case 'manual': return 'badge b-blue';
    case 'schedule': return 'badge b-purple';
    case 'webhook': return 'badge b-amber';
    case 'push': return 'badge b-green';
    default: return 'badge';
  }
}

function formatDuration(duration: string | null): string {
  return duration ?? '--';
}

function useRerunScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (scanId: string) => {
      return apiClient(`/scans/${scanId}/rerun`, { method: 'POST' });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['scan-queue'] });
    },
    onError: (err: Error) => {
      console.error('[CipherRadar] Failed to rerun scan:', err.message);
    },
  });
}

export function ScanQueue(): React.ReactElement {
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState('');
  const [triggerFilter, setTriggerFilter] = useState('');
  const [projectFilter, setProjectFilter] = useState('');
  const [page, setPage] = useState(1);
  const perPage = 25;

  const [promoteTarget, setPromoteTarget] = useState<ScanQueueItem | null>(null);

  const rerunScan = useRerunScan();
  const { data: projects } = useRepositories();

  const { data, isLoading, error } = useScanQueue({
    status: statusFilter || undefined,
    triggerType: triggerFilter || undefined,
    projectId: projectFilter || undefined,
    page,
    perPage,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const filterStyle: React.CSSProperties = {
    padding: '6px 10px',
    fontSize: '12px',
    background: 'var(--bg-2)',
    color: 'var(--text-1)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
  };

  return (
    <div>
      <div className="topbar">
        <h1 style={{ fontSize: '18px', fontWeight: 700 }}>Scan Queue</h1>
      </div>

      {/* Filters */}
      <div
        data-testid="scan-queue-filters"
        style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}
      >
        <select
          data-testid="filter-status"
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          style={filterStyle}
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        <select
          data-testid="filter-trigger"
          value={triggerFilter}
          onChange={(e) => { setTriggerFilter(e.target.value); setPage(1); }}
          style={filterStyle}
        >
          <option value="">All Triggers</option>
          {TRIGGER_OPTIONS.filter(Boolean).map((t) => (
            <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
          ))}
        </select>

        <select
          data-testid="filter-project"
          value={projectFilter}
          onChange={(e) => { setProjectFilter(e.target.value); setPage(1); }}
          style={filterStyle}
        >
          <option value="">All Projects</option>
          {(projects ?? []).map((p) => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
      </div>

      {isLoading && (
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading scans...</p>
        </div>
      )}

      {error && (
        <div className="card">
          <p style={{ color: 'var(--red)', fontSize: '13px' }}>Failed to load scan queue.</p>
        </div>
      )}

      {!isLoading && !error && (
        <div className="card">
          <AccessibleTable
            columns={[
              { label: 'Project' },
              { label: 'Trigger' },
              { label: 'Status' },
              { label: 'Environment' },
              { label: 'Started' },
              { label: 'Duration' },
              { label: 'Triggered By' },
              { label: 'Actions' },
            ]}
            caption="Scan queue"
            data-testid="scan-queue-table"
          >
              {items.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      icon={'\u25B6'}
                      title="No scans yet"
                      description="Import a project and trigger your first scan to see results here."
                      actionLabel="Run Your First Scan"
                      onAction={() => void navigate({ to: '/repos' })}
                    />
                  </td>
                </tr>
              )}
              {items.map((scan: ScanQueueItem) => (
                <tr key={scan.id} data-testid={`scan-row-${scan.id}`}>
                  <td>{scan.projectName}</td>
                  <td>
                    <span className={triggerBadgeClass(scan.triggerType)}>
                      {scan.triggerType}
                    </span>
                  </td>
                  <td>
                    <span className={statusBadgeClass(scan.status)}>
                      {scan.status}
                    </span>
                  </td>
                  <td>
                    {scan.environment ? <EnvironmentBadge environment={scan.environment} /> : '\u2014'}
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-3)' }}>{scan.startedAt}</td>
                  <td style={{ fontSize: '12px' }}>{formatDuration(scan.duration)}</td>
                  <td style={{ fontSize: '12px', color: 'var(--text-3)' }}>{scan.triggeredBy}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        className="btn btn-outline btn-sm"
                        onClick={() => rerunScan.mutate(scan.id)}
                        disabled={rerunScan.isPending}
                        data-testid={`rerun-${scan.id}`}
                        type="button"
                        style={{ fontSize: '11px', padding: '2px 8px' }}
                      >
                        Rerun
                      </button>
                      {scan.status === 'completed' && (
                        <button
                          className="btn btn-outline btn-sm"
                          onClick={() => setPromoteTarget(scan)}
                          data-testid={`promote-${scan.id}`}
                          type="button"
                          style={{ fontSize: '11px', padding: '2px 8px' }}
                        >
                          Promote
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
          </AccessibleTable>
        </div>
      )}

      {total > perPage && (
        <div style={{ marginTop: '16px' }}>
          <Pagination
            page={page}
            perPage={perPage}
            total={total}
            onPageChange={setPage}
            onPerPageChange={() => {}}
          />
        </div>
      )}

      {promoteTarget && (
        <PromoteModal
          scanId={promoteTarget.id}
          currentEnvironment={promoteTarget.environment ?? 'dev'}
          onClose={() => setPromoteTarget(null)}
        />
      )}
    </div>
  );
}
