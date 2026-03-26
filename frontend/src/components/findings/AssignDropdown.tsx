import { useState, useRef, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/api/client';
import { useAuth } from '@/lib/auth';
import { useToast } from '@/lib/use-toast';

interface ProjectMember {
  email: string;
  name: string;
  role: string;
}

interface AssignDropdownProps {
  findingId: string;
  projectId: string;
  currentAssignee: string | null;
}

export function AssignDropdown({
  findingId,
  projectId,
  currentAssignee,
}: AssignDropdownProps): React.ReactElement {
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const isDev = user?.role === 'developer';

  const { data: members } = useQuery<ProjectMember[]>({
    queryKey: ['project-members', projectId],
    queryFn: () => apiClient<ProjectMember[]>(`/projects/${projectId}/members`),
    staleTime: 60_000,
    enabled: open && !isDev,
  });

  const assignMutation = useMutation({
    mutationFn: async (assigneeEmail: string | null) => {
      return apiClient(`/findings/${findingId}/assign`, {
        method: 'PATCH',
        body: { assigneeEmail },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({ title: 'Finding assigned', variant: 'success' });
      setOpen(false);
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to assign',
        description: err.message,
        variant: 'error',
      });
    },
  });

  const handleAssign = useCallback(
    (email: string | null) => {
      assignMutation.mutate(email);
    },
    [assignMutation],
  );

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const displayName = currentAssignee ?? 'Unassigned';

  return (
    <div ref={dropdownRef} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        className="btn btn-outline"
        style={{ fontSize: '11px', padding: '2px 8px' }}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((prev) => !prev);
        }}
        data-testid="assign-dropdown-trigger"
      >
        {displayName}
      </button>

      {open && (
        <div
          className="card"
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            zIndex: 50,
            minWidth: '200px',
            padding: '4px 0',
            marginTop: '2px',
          }}
          data-testid="assign-dropdown-menu"
        >
          {isDev ? (
            // DEV only sees self-assign
            <button
              className="dropdown-item"
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
              onClick={(e) => {
                e.stopPropagation();
                handleAssign(user?.email ?? null);
              }}
              data-testid="assign-self"
            >
              Assign to me
            </button>
          ) : (
            <>
              {/* Unassign option */}
              <button
                className="dropdown-item"
                style={{
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  padding: '6px 12px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-3)',
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  handleAssign(null);
                }}
                data-testid="assign-unassign"
              >
                Unassigned
              </button>
              {/* Member list */}
              {(members ?? []).map((member) => (
                <button
                  key={member.email}
                  className="dropdown-item"
                  style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    padding: '6px 12px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    background:
                      member.email === currentAssignee ? 'var(--accent-dim)' : 'none',
                    border: 'none',
                    color: 'var(--text-1)',
                  }}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleAssign(member.email);
                  }}
                  data-testid={`assign-member-${member.email}`}
                >
                  {member.name}{' '}
                  <span style={{ color: 'var(--text-3)', fontSize: '10px' }}>
                    ({member.role})
                  </span>
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}
