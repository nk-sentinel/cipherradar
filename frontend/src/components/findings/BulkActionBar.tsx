import { useState, useCallback } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/api/client';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/lib/use-toast';
import type { Role } from '@/lib/roles';
import type { FindingStatus } from '@/mocks/data/findings';

// ---------------------------------------------------------------------------
// RBAC matrix for bulk actions (D19)
// ---------------------------------------------------------------------------

type BulkAction =
  | 'assign'
  | 'status_change'
  | 'mark_fp'
  | 'mark_ra'
  | 'raise_fp_request'
  | 'create_jira'
  | 'export';

const ACTION_LABELS: Record<BulkAction, string> = {
  assign: 'Assign',
  status_change: 'Status',
  mark_fp: 'Mark FP',
  mark_ra: 'Mark RA',
  raise_fp_request: 'Raise FP Request',
  create_jira: 'Create Jira',
  export: 'Export',
};

const ROLE_ACTIONS: Record<Role, BulkAction[]> = {
  'org-admin': ['assign', 'status_change', 'mark_fp', 'mark_ra', 'create_jira', 'export'],
  'security-manager': ['assign', 'status_change', 'mark_fp', 'mark_ra', 'create_jira', 'export'],
  'security-engineer': ['assign', 'status_change', 'create_jira', 'export'],
  'team-manager': ['assign', 'status_change', 'raise_fp_request', 'create_jira', 'export'],
  'compliance-auditor': ['export'],
  developer: ['raise_fp_request', 'export'],
  guest: [],
};

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'in_review', label: 'In Review' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'resolved', label: 'Resolved' },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface BulkActionBarProps {
  selectedIds: string[];
  onClear: () => void;
}

export function BulkActionBar({
  selectedIds,
  onClear,
}: BulkActionBarProps): React.ReactElement | null {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeMenu, setActiveMenu] = useState<'status' | 'more' | null>(null);

  const role = (user?.role ?? 'guest') as Role;
  const allowedActions = ROLE_ACTIONS[role] ?? [];

  const bulkMutation = useMutation({
    mutationFn: async (payload: { action: string; findingIds: string[]; payload?: Record<string, unknown> }) => {
      return apiClient('/findings/bulk', {
        method: 'POST',
        body: payload,
      });
    },
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({
        title: `Bulk action completed`,
        description: `${String(variables.findingIds.length)} findings updated (${variables.action}).`,
        variant: 'success',
      });
      onClear();
      setActiveMenu(null);
    },
    onError: (err: Error) => {
      toast({
        title: 'Bulk action failed',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const handleStatusChange = useCallback(
    (status: FindingStatus) => {
      bulkMutation.mutate({
        action: 'status_change',
        findingIds: selectedIds,
        payload: { status },
      });
    },
    [bulkMutation, selectedIds],
  );

  const handleAction = useCallback(
    (action: BulkAction) => {
      bulkMutation.mutate({
        action,
        findingIds: selectedIds,
      });
    },
    [bulkMutation, selectedIds],
  );

  if (selectedIds.length === 0) return null;

  const hasAssign = allowedActions.includes('assign');
  const hasStatus = allowedActions.includes('status_change');
  const moreActions = allowedActions.filter(
    (a) => !['assign', 'status_change'].includes(a),
  );

  return (
    <div
      className="card"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 12px',
        marginBottom: '8px',
        borderColor: 'var(--accent)',
      }}
      data-testid="bulk-action-bar"
    >
      <span style={{ fontSize: '12px', fontWeight: 600 }} data-testid="bulk-count">
        {selectedIds.length} selected
      </span>

      {hasAssign && (
        <button
          className="btn btn-outline"
          style={{ fontSize: '11px', padding: '2px 8px' }}
          onClick={() => handleAction('assign')}
          data-testid="bulk-assign"
        >
          Assign
        </button>
      )}

      {hasStatus && (
        <div style={{ position: 'relative' }}>
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '2px 8px' }}
            onClick={() => setActiveMenu(activeMenu === 'status' ? null : 'status')}
            data-testid="bulk-status"
          >
            Status &#x25BE;
          </button>
          {activeMenu === 'status' && (
            <div
              className="card"
              style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                zIndex: 50,
                padding: '4px 0',
                marginTop: '2px',
                minWidth: '140px',
              }}
              data-testid="bulk-status-menu"
            >
              {STATUS_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    padding: '6px 12px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-1)',
                  }}
                  onClick={() => handleStatusChange(opt.value)}
                  data-testid={`bulk-status-${opt.value}`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {moreActions.length > 0 && (
        <div style={{ position: 'relative' }}>
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '2px 8px' }}
            onClick={() => setActiveMenu(activeMenu === 'more' ? null : 'more')}
            data-testid="bulk-more"
          >
            More &#x25BE;
          </button>
          {activeMenu === 'more' && (
            <div
              className="card"
              style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                zIndex: 50,
                padding: '4px 0',
                marginTop: '2px',
                minWidth: '160px',
              }}
              data-testid="bulk-more-menu"
            >
              {moreActions.map((action) => (
                <button
                  key={action}
                  style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    padding: '6px 12px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-1)',
                  }}
                  onClick={() => handleAction(action)}
                  data-testid={`bulk-action-${action}`}
                >
                  {ACTION_LABELS[action]}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <button
        className="btn btn-outline"
        style={{ fontSize: '11px', padding: '2px 8px', marginLeft: 'auto' }}
        onClick={onClear}
        data-testid="bulk-clear"
      >
        Clear
      </button>
    </div>
  );
}
