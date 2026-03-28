import { useState, useMemo } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useRepositories } from '@/api/hooks/useRepositories.ts';
import { useTriggerScan } from '@/api/hooks/useTriggerScan.ts';
import { EmptyState } from '@/components/ui/EmptyState.tsx';
import { cn } from '@/lib/utils.ts';

function getComplianceColor(percent: number): string {
  if (percent >= 80) return 'var(--green)';
  if (percent >= 60) return 'var(--yellow)';
  if (percent >= 40) return 'var(--orange)';
  return 'var(--red)';
}

function getQuantumBadgeClass(score: number): string {
  if (score >= 80) return 'b-vuln';
  if (score >= 30) return 'b-med';
  return 'b-safe';
}

export function Repositories(): React.ReactElement {
  const { data: repos, isLoading, error } = useRepositories();
  const triggerScan = useTriggerScan();
  const [search, setSearch] = useState('');
  const navigate = useNavigate();

  const filtered = useMemo(() => {
    if (!repos) return [];
    if (!search.trim()) return repos;
    const q = search.toLowerCase();
    return repos.filter(
      (r) =>
        (r.name ?? '').toLowerCase().includes(q) ||
        (r.orgPath ?? '').toLowerCase().includes(q) ||
        (r.provider ?? '').toLowerCase().includes(q) ||
        (r.languages ?? []).some((l: string) => l.toLowerCase().includes(q)),
    );
  }, [repos, search]);

  if (isLoading) {
    return (
      <div>
        <div className="topbar">
          <h1>Repositories</h1>
        </div>
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <div className="topbar">
          <h1>Repositories</h1>
        </div>
        <div className="card">
          <p style={{ color: 'var(--red)', fontSize: '13px' }}>
            Failed to load repositories.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="topbar">
        <h1>Repositories</h1>
        <div className="topbar-right">
          <input
            className="input"
            style={{ width: '220px' }}
            placeholder="Search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button
            className="btn btn-accent"
            onClick={() => void navigate({ to: '/admin/integrations' })}
          >
            + Connect Repo
          </button>
        </div>
      </div>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Provider</th>
              <th scope="col">Languages</th>
              <th scope="col">Findings</th>
              <th scope="col">Compliance</th>
              <th scope="col">Quantum</th>
              <th scope="col">Last Scan</th>
              <th scope="col"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((repo) => (
              <tr
                key={repo.id}
                className={cn('clickable')}
                onClick={() =>
                  void navigate({
                    to: '/repos/$repoId/overview',
                    params: { repoId: repo.id },
                  })
                }
                data-testid={`repo-row-${repo.id}`}
              >
                <td>
                  <strong>{repo.name}</strong>
                  <br />
                  <span
                    style={{
                      fontSize: '10px',
                      color: 'var(--text-4)',
                    }}
                  >
                    {repo.orgPath ?? ''}
                  </span>
                </td>
                <td>{repo.provider ?? ''}</td>
                <td>{(repo.languages ?? []).join(', ')}</td>
                <td>{repo.findings ?? 0}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="progress" style={{ width: '70px' }}>
                      <div
                        className="progress-fill"
                        style={{
                          width: `${String(repo.compliancePercent ?? 0)}%`,
                          background: getComplianceColor(repo.compliancePercent ?? 0),
                        }}
                      />
                    </div>
                    <span>{repo.compliancePercent ?? 0}%</span>
                  </div>
                </td>
                <td>
                  <span className={cn('badge', getQuantumBadgeClass(repo.quantumScore ?? 0))}>
                    {repo.quantumScore ?? 0}
                  </span>
                </td>
                <td>{repo.lastScan ?? 'Never'}</td>
                <td>
                  <button
                    className="btn btn-outline"
                    disabled={triggerScan.isPending}
                    aria-label={`Scan ${repo.name}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      triggerScan.mutate(repo.id);
                    }}
                  >
                    {triggerScan.isPending ? 'Scanning...' : 'Scan'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && repos && repos.length === 0 && (
          <EmptyState
            icon={'\u2630'}
            title="No projects yet"
            description="Connect a Git provider to start importing repositories for cryptographic scanning."
            actionLabel="Connect a Git Provider"
            onAction={() => void navigate({ to: '/admin/integrations' })}
          />
        )}
        {filtered.length === 0 && repos && repos.length > 0 && (
          <EmptyState
            icon={'\u{1F50D}'}
            title="No repositories match your search"
            description="Try adjusting your search terms or clear the filter."
          />
        )}
      </div>
    </div>
  );
}
