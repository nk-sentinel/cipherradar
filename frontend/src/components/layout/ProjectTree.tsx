import { useState, useMemo } from 'react';
import { Link, useRouterState } from '@tanstack/react-router';
import { ChevronRight, ChevronDown, Folder, FileCode } from 'lucide-react';
import { useRepositories } from '@/api/hooks/useRepositories';
import { cn } from '@/lib/utils';

export interface EntityLabels {
  group: string;
  project: string;
}

export const DEFAULT_ENTITY_LABELS: EntityLabels = {
  group: 'Group',
  project: 'Project',
};

/**
 * Hook to get customizable entity labels from org settings.
 * Falls back to defaults if org context is not available.
 */
export function useEntityLabels(): EntityLabels {
  // In the future, read from org settings context
  // const { currentOrg } = useCurrentOrg();
  // return currentOrg?.entityLabels ?? DEFAULT_ENTITY_LABELS;
  return DEFAULT_ENTITY_LABELS;
}

/** Color pip for repository provider */
function providerColor(provider: string): string {
  switch (provider.toLowerCase()) {
    case 'github':
      return '#6e5494';
    case 'gitlab':
      return '#fc6d26';
    case 'bitbucket':
      return '#0052cc';
    default:
      return 'var(--accent)';
  }
}

interface GroupNode {
  name: string;
  repos: Array<{
    id: string;
    name: string;
    provider: string;
  }>;
}

/**
 * Collapsible group > project tree in the sidebar.
 * Groups expand to show projects with a colored pip by provider.
 */
export function ProjectTree(): React.ReactElement {
  const { data: repos } = useRepositories();
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;
  const labels = useEntityLabels();

  // Group repos by org path prefix
  const groups = useMemo((): GroupNode[] => {
    if (!repos || !Array.isArray(repos)) return [];

    const groupMap = new Map<string, GroupNode>();

    for (const repo of repos) {
      const orgPath = (repo as unknown as Record<string, unknown>).orgPath as string | undefined;
      const groupName = orgPath ? (orgPath.split('/')[0] ?? 'Default') : (repo.name?.charAt(0)?.toUpperCase() ?? 'Default');

      if (!groupMap.has(groupName)) {
        groupMap.set(groupName, { name: groupName, repos: [] });
      }

      groupMap.get(groupName)?.repos.push({
        id: repo.id,
        name: repo.name,
        provider: repo.provider,
      });
    }

    return Array.from(groupMap.values());
  }, [repos]);

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(() => {
    // Auto-expand the first group
    if (groups.length > 0 && groups[0]) {
      return new Set([groups[0].name]);
    }
    return new Set();
  });

  const toggleGroup = (name: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  };

  if (groups.length === 0) {
    return (
      <div style={{ padding: '8px 16px', fontSize: '10px', color: 'var(--text-4)' }}>
        No {labels.project.toLowerCase()}s yet
      </div>
    );
  }

  return (
    <div data-testid="project-tree" style={{ marginBottom: '8px' }}>
      <div
        className="nav-section"
        style={{ display: 'flex', alignItems: 'center', gap: '4px' }}
      >
        {labels.group}s / {labels.project}s
      </div>

      {groups.map((group) => {
        const isExpanded = expandedGroups.has(group.name);

        return (
          <div key={group.name}>
            {/* Group header */}
            <button
              onClick={() => toggleGroup(group.name)}
              aria-expanded={isExpanded}
              aria-label={`Toggle ${group.name} ${labels.group.toLowerCase()}`}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                width: '100%',
                padding: '4px 16px',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontSize: '11px',
                color: 'var(--text-2)',
                fontFamily: 'inherit',
              }}
            >
              {isExpanded ? (
                <ChevronDown size={12} style={{ flexShrink: 0 }} />
              ) : (
                <ChevronRight size={12} style={{ flexShrink: 0 }} />
              )}
              <Folder size={12} style={{ flexShrink: 0, color: 'var(--accent)' }} />
              <span
                style={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {group.name}
              </span>
              <span
                style={{
                  marginLeft: 'auto',
                  fontSize: '9px',
                  color: 'var(--text-4)',
                }}
              >
                {group.repos.length}
              </span>
            </button>

            {/* Project items */}
            {isExpanded &&
              group.repos.map((repo) => {
                const repoPath = `/repos/${repo.id}`;
                const isActive = currentPath.startsWith(repoPath);

                return (
                  <Link
                    key={repo.id}
                    to={`/repos/${repo.id}/overview` as any}
                    className={cn('nav-item', isActive && 'active')}
                    style={{
                      paddingLeft: '36px',
                      fontSize: '11px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                    }}
                  >
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: providerColor(repo.provider),
                        flexShrink: 0,
                      }}
                    />
                    <FileCode size={11} style={{ flexShrink: 0, color: 'var(--text-3)' }} />
                    <span
                      style={{
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {repo.name}
                    </span>
                  </Link>
                );
              })}
          </div>
        );
      })}
    </div>
  );
}
