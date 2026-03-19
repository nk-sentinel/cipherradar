import { useState, useMemo } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useRepositories } from '@/api/hooks/useRepositories.ts';
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
  const [search, setSearch] = useState('');
  const navigate = useNavigate();

  const filtered = useMemo(() => {
    if (!repos) return [];
    if (!search.trim()) return repos;
    const q = search.toLowerCase();
    return repos.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.orgPath.toLowerCase().includes(q) ||
        r.provider.toLowerCase().includes(q) ||
        r.languages.some((l) => l.toLowerCase().includes(q)),
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
          <button className="btn btn-accent">+ Connect Repo</button>
        </div>
      </div>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Provider</th>
              <th>Languages</th>
              <th>Findings</th>
              <th>Compliance</th>
              <th>Quantum</th>
              <th>Last Scan</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((repo) => (
              <tr
                key={repo.id}
                className={cn('clickable')}
                onClick={() =>
                  void navigate({ to: `/repos/${repo.id}/overview` as string })
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
                    {repo.orgPath}
                  </span>
                </td>
                <td>{repo.provider}</td>
                <td>{repo.languages.join(', ')}</td>
                <td>{repo.findings}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="progress" style={{ width: '70px' }}>
                      <div
                        className="progress-fill"
                        style={{
                          width: `${String(repo.compliancePercent)}%`,
                          background: getComplianceColor(repo.compliancePercent),
                        }}
                      />
                    </div>
                    <span>{repo.compliancePercent}%</span>
                  </div>
                </td>
                <td>
                  <span className={cn('badge', getQuantumBadgeClass(repo.quantumScore))}>
                    {repo.quantumScore}
                  </span>
                </td>
                <td>{repo.lastScan}</td>
                <td>
                  <button
                    className="btn btn-outline"
                    onClick={(e) => {
                      e.stopPropagation();
                    }}
                  >
                    Scan
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
