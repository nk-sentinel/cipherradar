import { useState, useCallback } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useAuth } from '@/lib/auth.tsx';
import { useGroups, useGroupDetail, useCreateGroup, type Group } from '@/api/hooks/useGroups.ts';
import { useOrgSettings } from '@/api/hooks/useAdmin.ts';
import { AccessibleTable } from '@/components/ui/AccessibleTable.tsx';
import { JiraConfigSection } from '@/components/settings/JiraConfigSection.tsx';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

// ---------------------------------------------------------------------------
// Page export
// ---------------------------------------------------------------------------

export function GroupManagement(): React.ReactElement {
  return (
    <RequireRole
      roles={['org-admin', 'security-manager']}
      fallback={
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
            Access denied. You do not have permission to manage groups. Contact your admin.
          </p>
        </div>
      }
    >
      <GroupManagementContent />
    </RequireRole>
  );
}

// ---------------------------------------------------------------------------
// Add Group Modal
// ---------------------------------------------------------------------------

function AddGroupModal({
  onClose,
  groupLabel,
}: {
  onClose: () => void;
  groupLabel: string;
}): React.ReactElement {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const createGroup = useCreateGroup();

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (!name.trim()) return;
      createGroup.mutate(
        { name: name.trim(), description: description.trim() },
        { onSuccess: () => onClose() },
      );
    },
    [name, description, createGroup, onClose],
  );

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
      data-testid="add-group-modal-backdrop"
    >
      <div
        className="card"
        style={{ width: '420px', maxWidth: '90vw' }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px' }}>
          Add {groupLabel}
        </h2>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '12px' }}>
            <label
              htmlFor="group-name"
              style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}
            >
              Name
            </label>
            <input
              id="group-name"
              className="input"
              type="text"
              placeholder={`${groupLabel} name`}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
              data-testid="group-name-input"
            />
          </div>
          <div style={{ marginBottom: '16px' }}>
            <label
              htmlFor="group-description"
              style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}
            >
              Description
            </label>
            <input
              id="group-description"
              className="input"
              type="text"
              placeholder="Optional description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="group-description-input"
            />
          </div>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button
              type="button"
              className="btn btn-outline"
              style={{ fontSize: '12px' }}
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ fontSize: '12px' }}
              disabled={!name.trim() || createGroup.isPending}
              data-testid="create-group-btn"
            >
              {createGroup.isPending ? 'Creating...' : `Create ${groupLabel}`}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Group Detail Drawer
// ---------------------------------------------------------------------------

function GroupDetailDrawer({
  groupId,
  onClose,
  groupLabel,
}: {
  groupId: string;
  onClose: () => void;
  groupLabel: string;
}): React.ReactElement {
  const { data: detail, isLoading } = useGroupDetail(groupId);

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.3)',
        display: 'flex',
        justifyContent: 'flex-end',
        zIndex: 1000,
      }}
      onClick={onClose}
      data-testid="group-detail-backdrop"
    >
      <div
        className="card"
        style={{
          width: '400px',
          maxWidth: '90vw',
          height: '100vh',
          borderRadius: 0,
          overflowY: 'auto',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 700 }}>
            {groupLabel} Detail
          </h2>
          <button
            className="btn btn-outline"
            style={{ fontSize: '11px', padding: '2px 8px' }}
            onClick={onClose}
          >
            Close
          </button>
        </div>

        {isLoading && (
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
        )}

        {detail && (
          <>
            <div style={{ marginBottom: '16px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 600 }}>{detail.name}</h3>
              {detail.description && (
                <p style={{ fontSize: '12px', color: 'var(--text-2)', marginTop: '4px' }}>
                  {detail.description}
                </p>
              )}
            </div>

            <div style={{ marginBottom: '16px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                Members ({detail.members.length})
              </h4>
              {detail.members.length === 0 ? (
                <p style={{ fontSize: '11px', color: 'var(--text-3)' }}>No members</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {detail.members.map((m) => (
                    <div
                      key={m.email}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '11px',
                        padding: '4px 8px',
                        background: 'var(--surface-2)',
                        borderRadius: 'var(--radius)',
                      }}
                    >
                      <span>{m.name}</span>
                      <span style={{ color: 'var(--text-3)' }}>{m.role}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <h4 style={{ fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                Projects ({detail.projects.length})
              </h4>
              {detail.projects.length === 0 ? (
                <p style={{ fontSize: '11px', color: 'var(--text-3)' }}>No projects</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {detail.projects.map((p) => (
                    <div
                      key={p.id}
                      style={{
                        fontSize: '11px',
                        padding: '4px 8px',
                        background: 'var(--surface-2)',
                        borderRadius: 'var(--radius)',
                      }}
                    >
                      {p.name}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Jira Integration (D18) */}
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                Jira Integration
              </h4>
              <JiraConfigSection scopeType="group" scopeId={groupId} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

function GroupManagementContent(): React.ReactElement {
  const { user } = useAuth();
  const isOrgAdmin = user?.role === 'org-admin';

  const { data: groups, isLoading, error } = useGroups();
  const { data: orgSettings } = useOrgSettings();

  const groupLabel = orgSettings?.labels?.groupLabel || 'Group';

  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  const handleRowClick = useCallback((group: Group) => {
    setSelectedGroupId(group.id);
  }, []);

  if (isLoading && !groups) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error && !groups) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load groups.
        </p>
      </div>
    );
  }

  const items = groups ?? [];

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}
      >
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
            letterSpacing: '0.04em',
          }}
        >
          {groupLabel}s
        </h1>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ color: 'var(--text-3)', fontSize: '11px' }}>
            {items.length} {groupLabel.toLowerCase()}{items.length !== 1 ? 's' : ''}
          </span>
          {isOrgAdmin && (
            <button
              className="btn btn-primary"
              style={{ fontSize: '11px', padding: '4px 10px' }}
              onClick={() => setShowAddModal(true)}
              data-testid="add-group-btn"
            >
              Add {groupLabel}
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <AccessibleTable
          columns={[
            { label: `${groupLabel} Name` },
            { label: 'Project Count' },
            { label: 'Member Count' },
            { label: 'Created' },
          ]}
          caption={`${groupLabel} management table`}
          data-testid="groups-table"
        >
          {items.length === 0 && (
            <tr>
              <td
                colSpan={4}
                style={{ textAlign: 'center', color: 'var(--text-3)', fontSize: '12px', padding: '20px' }}
              >
                No {groupLabel.toLowerCase()}s found. {isOrgAdmin && `Click "Add ${groupLabel}" to create one.`}
              </td>
            </tr>
          )}
          {items.map((group) => (
            <tr
              key={group.id}
              data-testid={`group-row-${group.id}`}
              style={{ cursor: 'pointer' }}
              onClick={() => handleRowClick(group)}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  handleRowClick(group);
                }
              }}
            >
              <td style={{ fontWeight: 500, fontSize: '12px' }}>{group.name}</td>
              <td style={{ fontSize: '12px' }}>{group.projectCount}</td>
              <td style={{ fontSize: '12px' }}>{group.memberCount}</td>
              <td style={{ fontSize: '11px', color: 'var(--text-3)' }}>
                {formatDate(group.createdAt)}
              </td>
            </tr>
          ))}
        </AccessibleTable>
      </div>

      {/* Add Group Modal */}
      {showAddModal && (
        <AddGroupModal
          onClose={() => setShowAddModal(false)}
          groupLabel={groupLabel}
        />
      )}

      {/* Group Detail Drawer */}
      {selectedGroupId && (
        <GroupDetailDrawer
          groupId={selectedGroupId}
          onClose={() => setSelectedGroupId(null)}
          groupLabel={groupLabel}
        />
      )}
    </div>
  );
}
