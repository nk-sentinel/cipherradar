import { useState, useCallback } from 'react';
import { useFindings, type FindingsFilters, type Severity, type QuantumStatus } from '@/api/hooks/useFindings';
import { SeverityBadge } from '@/components/findings/SeverityBadge';
import { QuantumBadge } from '@/components/findings/QuantumBadge';
import { FindingDetail } from '@/components/findings/FindingDetail';
import { cn } from '@/lib/utils';
import type { Finding } from '@/mocks/data/findings';

type FilterType = 'all' | 'critical' | 'high' | 'medium' | 'quantum-vulnerable' | 'broken';

interface RepoFindingsProps {
  repoId: string;
}

export function RepoFindings({ repoId }: RepoFindingsProps): React.ReactElement {
  const [activeFilter, setActiveFilter] = useState<FilterType>('all');
  const [search, setSearch] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const filters: FindingsFilters = {};
  if (activeFilter === 'critical') filters.severity = 'critical' as Severity;
  else if (activeFilter === 'high') filters.severity = 'high' as Severity;
  else if (activeFilter === 'medium') filters.severity = 'medium' as Severity;
  else if (activeFilter === 'quantum-vulnerable') filters.quantumStatus = 'vulnerable' as QuantumStatus;
  else if (activeFilter === 'broken') filters.quantumStatus = 'broken' as QuantumStatus;
  if (search.trim()) filters.search = search.trim();

  const { data, isLoading, error } = useFindings(repoId, filters);

  const handleFilterClick = useCallback((filter: FilterType) => {
    setActiveFilter(filter);
    setSelectedFinding(null);
  }, []);

  const handleRowClick = useCallback((finding: Finding) => {
    setSelectedFinding((prev) => (prev?.id === finding.id ? null : finding));
  }, []);

  const handleCloseDetail = useCallback(() => {
    setSelectedFinding(null);
  }, []);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading findings...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>Failed to load findings.</p>
      </div>
    );
  }

  const findings = data?.findings ?? [];
  const counts = data?.counts ?? {
    all: 0,
    critical: 0,
    high: 0,
    medium: 0,
    quantumVulnerable: 0,
    broken: 0,
  };

  const filterButtons: { key: FilterType; label: string; count?: number }[] = [
    { key: 'all', label: 'All', count: counts.all },
    { key: 'critical', label: 'Critical', count: counts.critical },
    { key: 'high', label: 'High', count: counts.high },
    { key: 'medium', label: 'Medium', count: counts.medium },
    { key: 'quantum-vulnerable', label: 'Quantum Vulnerable' },
    { key: 'broken', label: 'Broken' },
  ];

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
          Findings
        </h1>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <input
            className="input"
            style={{ width: '200px' }}
            placeholder="Search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Filter bar */}
      <div className="filters">
        {filterButtons.map((fb) => (
          <button
            key={fb.key}
            className={cn('filter', activeFilter === fb.key && 'active')}
            onClick={() => handleFilterClick(fb.key)}
          >
            {fb.label}
            {fb.count !== undefined ? ` (${fb.count})` : ''}
          </button>
        ))}
      </div>

      {/* Findings table */}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>File</th>
              <th>Finding</th>
              <th>Algorithm</th>
              <th>Quantum</th>
              <th>Pass</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-3)' }}>
                  No findings match the current filters.
                </td>
              </tr>
            ) : (
              findings.map((finding) => (
                <tr
                  key={finding.id}
                  className="clickable"
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleRowClick(finding)}
                  data-testid={`finding-row-${finding.id}`}
                >
                  <td>
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td>
                    {finding.file}:{finding.line}
                  </td>
                  <td>{finding.title}</td>
                  <td>{finding.algorithm ?? '\u2014'}</td>
                  <td>
                    <QuantumBadge status={finding.quantumStatus} />
                  </td>
                  <td>{finding.pass}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Finding detail panel */}
      {selectedFinding && (
        <FindingDetail finding={selectedFinding} onClose={handleCloseDetail} />
      )}
    </div>
  );
}
