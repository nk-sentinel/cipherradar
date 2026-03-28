import { useState, useCallback, useMemo } from 'react';
import {
  useFindings,
  type FindingsFilters,
  type Severity,
  type QuantumStatus,
  type SortField,
  type SortDirection,
} from '@/api/hooks/useFindings';
import { SeverityBadge } from '@/components/findings/SeverityBadge';
import { EmptyState } from '@/components/ui/EmptyState';
import { QuantumBadge } from '@/components/findings/QuantumBadge';
import { FindingStatusBadge } from '@/components/findings/FindingStatusBadge';
import { DetectionBadge } from '@/components/findings/DetectionBadge';
import {
  FindingStatusFilter,
  DEFAULT_ACTIVE_STATUSES,
  ALL_STATUSES,
} from '@/components/findings/FindingStatusFilter';
import { FindingDetail } from '@/components/findings/FindingDetail';
import { BulkActionBar } from '@/components/findings/BulkActionBar';
import { Pagination } from '@/components/ui/Pagination';
import { cn } from '@/lib/utils';
import type { Finding, FindingStatus } from '@/mocks/data/findings';

type FilterType = 'all' | 'critical' | 'high' | 'medium' | 'quantum-vulnerable' | 'broken';

interface RepoFindingsProps {
  repoId: string;
}

function SortArrow({ active, direction }: { active: boolean; direction: SortDirection }): React.ReactElement | null {
  if (!active) return <span className="sort-arrow" style={{ opacity: 0.3 }}>{'\u25B4'}</span>;
  return (
    <span className="sort-arrow" data-testid="sort-indicator">
      {direction === 'asc' ? '\u25B4' : '\u25BE'}
    </span>
  );
}

export function RepoFindings({ repoId }: RepoFindingsProps): React.ReactElement {
  const [activeFilter, setActiveFilter] = useState<FilterType>('all');
  const [search, setSearch] = useState('');
  const [viewMode, setViewMode] = useState<'list' | 'file'>('list');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeStatuses, setActiveStatuses] = useState<FindingStatus[]>([...DEFAULT_ACTIVE_STATUSES]);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(25);
  const [sortField, setSortField] = useState<SortField>('severity');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());

  const toggleFileExpand = useCallback((filePath: string) => {
    setExpandedFiles((prev) => {
      const next = new Set(prev);
      if (next.has(filePath)) {
        next.delete(filePath);
      } else {
        next.add(filePath);
      }
      return next;
    });
  }, []);

  const filters: FindingsFilters = {
    page,
    perPage,
    sortField,
    sortDirection,
    statuses: activeStatuses,
  };
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
    setSelectedIds([]);
    setPage(1);
  }, []);

  const handleRowClick = useCallback((finding: Finding) => {
    setSelectedFinding((prev) => (prev?.id === finding.id ? null : finding));
  }, []);

  const handleCloseDetail = useCallback(() => {
    setSelectedFinding(null);
  }, []);

  const handleStatusToggle = useCallback((status: FindingStatus | 'all') => {
    if (status === 'all') {
      setActiveStatuses([...ALL_STATUSES]);
    } else {
      setActiveStatuses((prev) => {
        if (prev.includes(status)) {
          const next = prev.filter((s) => s !== status);
          return next.length === 0 ? [...ALL_STATUSES] : next;
        }
        return [...prev, status];
      });
    }
    setPage(1);
    setSelectedIds([]);
  }, []);

  const handleSort = useCallback((field: SortField) => {
    setSortField((prev) => {
      if (prev === field) {
        setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
        return prev;
      }
      setSortDirection('desc');
      return field;
    });
    setPage(1);
  }, []);

  const handlePageChange = useCallback((newPage: number) => {
    setPage(newPage);
    setSelectedFinding(null);
    setSelectedIds([]);
  }, []);

  const handlePerPageChange = useCallback((newPerPage: number) => {
    setPerPage(newPerPage);
    setPage(1);
    setSelectedFinding(null);
    setSelectedIds([]);
  }, []);

  const handleCheckboxToggle = useCallback((findingId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds((prev) =>
      prev.includes(findingId)
        ? prev.filter((id) => id !== findingId)
        : [...prev, findingId],
    );
  }, []);

  const handleSelectAllOnPage = useCallback(() => {
    const findings = data?.findings ?? [];
    const pageIds = findings.map((f) => f.id);
    setSelectedIds((prev) => {
      const allSelected = pageIds.every((id) => prev.includes(id));
      if (allSelected) {
        return prev.filter((id) => !pageIds.includes(id));
      }
      return [...new Set([...prev, ...pageIds])];
    });
  }, [data?.findings]);

  const handleClearSelection = useCallback(() => {
    setSelectedIds([]);
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
  const total = data?.total ?? 0;
  const counts = data?.counts ?? {
    all: 0,
    critical: 0,
    high: 0,
    medium: 0,
    quantumVulnerable: 0,
    broken: 0,
  };
  const statusCounts = data?.statusCounts ?? {
    open: 0,
    in_review: 0,
    in_progress: 0,
    resolved: 0,
    risk_accepted: 0,
    false_positive: 0,
  };

  const filterButtons: { key: FilterType; label: string; count?: number }[] = [
    { key: 'all', label: 'All', count: counts.all },
    { key: 'critical', label: 'Critical', count: counts.critical },
    { key: 'high', label: 'High', count: counts.high },
    { key: 'medium', label: 'Medium', count: counts.medium },
    { key: 'quantum-vulnerable', label: 'Quantum Vulnerable' },
    { key: 'broken', label: 'Broken' },
  ];

  const sortableHeaders: { field: SortField; label: string }[] = [
    { field: 'severity', label: 'Severity' },
  ];

  const pageIds = findings.map((f) => f.id);
  const allOnPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.includes(id));
  const hasActiveFilter = activeFilter !== 'all' || search.trim() !== '' || activeStatuses.length !== ALL_STATUSES.length;

  const groupedByFile = useMemo(() => {
    const groups: { filePath: string; findings: Finding[] }[] = [];
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      const existing = map.get(f.file);
      if (existing) {
        existing.push(f);
      } else {
        const arr = [f];
        map.set(f.file, arr);
        groups.push({ filePath: f.file, findings: arr });
      }
    }
    return groups;
  }, [findings]);

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

      {/* Status filter bar */}
      <FindingStatusFilter
        counts={statusCounts}
        totalCount={counts.all}
        activeStatuses={activeStatuses}
        onToggle={handleStatusToggle}
      />

      {/* Severity filter bar */}
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

      {/* View mode toggle */}
      <div style={{ display: 'flex', gap: '4px', marginBottom: '12px' }}>
        <button
          className={cn('btn', viewMode === 'list' ? 'btn-accent' : 'btn-outline')}
          style={{ padding: '4px 12px', fontSize: '11px' }}
          onClick={() => setViewMode('list')}
        >
          List
        </button>
        <button
          className={cn('btn', viewMode === 'file' ? 'btn-accent' : 'btn-outline')}
          style={{ padding: '4px 12px', fontSize: '11px' }}
          onClick={() => setViewMode('file')}
        >
          Group by File
        </button>
      </div>

      {/* Bulk action bar */}
      <BulkActionBar selectedIds={selectedIds} onClear={handleClearSelection} />

      {/* Findings table */}
      <div className="card">
        {viewMode === 'file' && findings.length > 0 ? (
          /* File-grouped view */
          <div>
            {groupedByFile.map((group) => {
              const isExpanded = expandedFiles.has(group.filePath);
              return (
                <div key={group.filePath} style={{ borderBottom: '1px solid var(--border)' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '8px 12px',
                      cursor: 'pointer',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'var(--text-1)',
                      background: isExpanded ? 'var(--bg-2)' : 'transparent',
                    }}
                    onClick={() => toggleFileExpand(group.filePath)}
                    data-testid={`file-group-${group.filePath}`}
                  >
                    <span style={{ fontSize: '10px', width: '12px' }}>{isExpanded ? '\u25BE' : '\u25B8'}</span>
                    <span style={{ fontFamily: 'var(--font)', fontSize: '11px' }}>{group.filePath}</span>
                    <span className="badge b-blue" style={{ fontSize: '9px', padding: '1px 5px' }}>
                      {group.findings.length}
                    </span>
                  </div>
                  {isExpanded && (
                    <table style={{ marginBottom: 0 }}>
                      <tbody>
                        {group.findings.map((finding) => (
                          <tr
                            key={finding.id}
                            className={cn('clickable', selectedIds.includes(finding.id) && 'selected')}
                            style={{ cursor: 'pointer' }}
                            onClick={() => handleRowClick(finding)}
                          >
                            <td style={{ padding: '6px', width: '32px' }}>
                              <input
                                type="checkbox"
                                checked={selectedIds.includes(finding.id)}
                                onClick={(e) => handleCheckboxToggle(finding.id, e)}
                                onChange={() => { /* controlled via onClick */ }}
                                aria-label={`Select ${finding.title}`}
                              />
                            </td>
                            <td><SeverityBadge severity={finding.severity} /></td>
                            <td style={{ fontSize: '11px', color: 'var(--text-3)' }}>L{finding.line}</td>
                            <td>{finding.title}</td>
                            <td>{finding.algorithm ?? '\u2014'}</td>
                            <td><QuantumBadge status={finding.quantumStatus} /></td>
                            <td><DetectionBadge pass={finding.pass} /></td>
                            <td><FindingStatusBadge status={finding.status} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
        <table>
          <thead>
            <tr>
              <th scope="col" style={{ width: '32px', padding: '6px' }}>
                <input
                  type="checkbox"
                  checked={allOnPageSelected}
                  onChange={handleSelectAllOnPage}
                  aria-label="Select all on page"
                  data-testid="select-all-checkbox"
                />
              </th>
              {sortableHeaders.map((h) => (
                <th
                  scope="col"
                  key={h.field}
                  className="sortable-header"
                  style={{ cursor: 'pointer', userSelect: 'none' }}
                  onClick={() => handleSort(h.field)}
                  data-testid={`sort-header-${h.field}`}
                >
                  {h.label}{' '}
                  <SortArrow active={sortField === h.field} direction={sortDirection} />
                </th>
              ))}
              <th
                scope="col"
                className="sortable-header"
                style={{ cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleSort('file')}
                data-testid="sort-header-file"
              >
                File{' '}
                <SortArrow active={sortField === 'file'} direction={sortDirection} />
              </th>
              <th
                scope="col"
                className="sortable-header"
                style={{ cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleSort('title')}
                data-testid="sort-header-title"
              >
                Finding{' '}
                <SortArrow active={sortField === 'title'} direction={sortDirection} />
              </th>
              <th
                scope="col"
                className="sortable-header"
                style={{ cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleSort('algorithm')}
                data-testid="sort-header-algorithm"
              >
                Algorithm{' '}
                <SortArrow active={sortField === 'algorithm'} direction={sortDirection} />
              </th>
              <th scope="col">Quantum</th>
              <th scope="col" title="How this finding was detected — Pattern: syntax matching, Taint: data flow analysis">
                Detection
              </th>
              <th
                scope="col"
                className="sortable-header"
                style={{ cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleSort('firstSeen')}
                data-testid="sort-header-firstSeen"
              >
                First Seen{' '}
                <SortArrow active={sortField === 'firstSeen'} direction={sortDirection} />
              </th>
              <th
                scope="col"
                className="sortable-header"
                style={{ cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleSort('confidence')}
                data-testid="sort-header-confidence"
              >
                Confidence{' '}
                <SortArrow active={sortField === 'confidence'} direction={sortDirection} />
              </th>
              <th
                scope="col"
                className="sortable-header"
                style={{ cursor: 'pointer', userSelect: 'none' }}
                onClick={() => handleSort('status')}
                data-testid="sort-header-status"
              >
                Status{' '}
                <SortArrow active={sortField === 'status'} direction={sortDirection} />
              </th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td colSpan={10}>
                  <EmptyState
                    icon={'\u2713'}
                    title="No findings match"
                    description="No findings match the current filters. Try adjusting or clearing your filters."
                    actionLabel="Clear Filters"
                    onAction={() => {
                      setActiveFilter('all');
                      setSearch('');
                      setActiveStatuses([...ALL_STATUSES]);
                      setPage(1);
                    }}
                  />
                </td>
              </tr>
            ) : (
              findings.map((finding) => (
                <tr
                  key={finding.id}
                  className={cn('clickable', selectedIds.includes(finding.id) && 'selected')}
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleRowClick(finding)}
                  data-testid={`finding-row-${finding.id}`}
                >
                  <td style={{ padding: '6px' }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(finding.id)}
                      onClick={(e) => handleCheckboxToggle(finding.id, e)}
                      onChange={() => { /* controlled via onClick */ }}
                      aria-label={`Select ${finding.title}`}
                      data-testid={`checkbox-${finding.id}`}
                    />
                  </td>
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
                  <td>
                    <DetectionBadge pass={finding.pass} />
                  </td>
                  <td style={{ fontSize: '11px', color: 'var(--text-3)' }}>{finding.firstSeen}</td>
                  <td>
                    <span className={cn('badge', finding.confidence === 'high' ? 'b-safe' : finding.confidence === 'medium' ? 'b-med' : 'b-vuln')}>
                      {finding.confidence}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <FindingStatusBadge status={finding.status} />
                      {finding.jiraIssueUrl && (
                        <a
                          href={finding.jiraIssueUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Jira Issue"
                          onClick={(e) => e.stopPropagation()}
                          style={{
                            fontSize: '14px',
                            textDecoration: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                          }}
                          data-testid={`jira-link-${finding.id}`}
                        >
                          {'\u2611'}
                        </a>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        )}

        {/* Select all matching filter link */}
        {hasActiveFilter && findings.length > 0 && selectedIds.length > 0 && (
          <div style={{ padding: '4px 8px', fontSize: '11px', color: 'var(--accent)' }}>
            <button
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--accent)',
                cursor: 'pointer',
                fontSize: '11px',
                textDecoration: 'underline',
              }}
              onClick={() => {
                const allIds = findings.map((f) => f.id);
                setSelectedIds(allIds);
              }}
              data-testid="select-all-matching"
            >
              Select all {total} matching filter
            </button>
          </div>
        )}

        {/* Pagination */}
        <Pagination
          page={page}
          perPage={perPage}
          total={total}
          onPageChange={handlePageChange}
          onPerPageChange={handlePerPageChange}
        />
      </div>

      {/* Finding detail panel */}
      {selectedFinding && (
        <FindingDetail finding={selectedFinding} onClose={handleCloseDetail} />
      )}
    </div>
  );
}
