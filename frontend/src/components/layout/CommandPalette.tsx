import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useSearch } from '@/api/hooks/useSearch';
import type { SearchResult } from '@/api/hooks/useSearch';
import { Search, FolderKanban, AlertTriangle, X } from 'lucide-react';

/**
 * Global command palette accessible via Ctrl+K (or Cmd+K on Mac).
 * Searches projects and findings with instant results.
 */
export function CommandPalette(): React.ReactElement {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  // Debounced query
  const [debouncedQuery, setDebouncedQuery] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query), 200);
    return () => clearTimeout(timer);
  }, [query]);

  const { data: searchData } = useSearch(debouncedQuery);
  const results = searchData?.results ?? [];

  // Open/close with Ctrl+K / Cmd+K
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen((prev) => !prev);
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Focus input when opening
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Reset selection when results change
  useEffect(() => {
    setSelectedIndex(0);
  }, [results.length]);

  const navigateToResult = useCallback(
    (result: SearchResult) => {
      setIsOpen(false);
      if (result.type === 'project') {
        void navigate({ to: `/repos/${result.id}/overview` });
      } else {
        void navigate({ to: `/repos/${result.repoId}/findings` });
      }
    },
    [navigate],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => Math.min(prev + 1, results.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter' && results[selectedIndex]) {
        e.preventDefault();
        navigateToResult(results[selectedIndex]);
      }
    },
    [results, selectedIndex, navigateToResult],
  );

  if (!isOpen) return <></>;

  return (
    <div
      data-testid="command-palette-overlay"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.5)',
        zIndex: 100,
        display: 'flex',
        justifyContent: 'center',
        paddingTop: '20vh',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) setIsOpen(false);
      }}
    >
      <div
        data-testid="command-palette"
        style={{
          width: '560px',
          maxHeight: '400px',
          background: 'var(--bg-1)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          boxShadow: '0 16px 48px rgba(0, 0, 0, 0.4)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Search input */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '12px 16px',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <Search size={16} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
          <input
            ref={inputRef}
            data-testid="command-palette-input"
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search projects, findings, algorithms..."
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text-1)',
              fontSize: '14px',
              fontFamily: 'inherit',
            }}
          />
          <button
            onClick={() => setIsOpen(false)}
            aria-label="Close search"
            style={{
              background: 'var(--bg-3)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              padding: '2px 6px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              color: 'var(--text-3)',
            }}
          >
            <X size={12} />
          </button>
        </div>

        {/* Results */}
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {query.length < 2 && (
            <div
              style={{
                padding: '24px 16px',
                textAlign: 'center',
                color: 'var(--text-3)',
                fontSize: '12px',
              }}
            >
              Type at least 2 characters to search...
            </div>
          )}

          {query.length >= 2 && results.length === 0 && (
            <div
              style={{
                padding: '24px 16px',
                textAlign: 'center',
                color: 'var(--text-3)',
                fontSize: '12px',
              }}
            >
              No results found for &ldquo;{query}&rdquo;
            </div>
          )}

          {results.map((result, index) => (
            <div
              key={`${result.type}-${result.id}`}
              data-testid={`search-result-${result.id}`}
              role="option"
              aria-selected={index === selectedIndex}
              onClick={() => navigateToResult(result)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px 16px',
                cursor: 'pointer',
                background:
                  index === selectedIndex ? 'var(--accent-dim)' : 'transparent',
                borderBottom: '1px solid var(--border-light)',
              }}
            >
              {result.type === 'project' ? (
                <FolderKanban
                  size={14}
                  style={{ color: 'var(--accent)', flexShrink: 0 }}
                />
              ) : (
                <AlertTriangle
                  size={14}
                  style={{
                    color:
                      result.severity === 'critical'
                        ? 'var(--red)'
                        : result.severity === 'high'
                          ? 'var(--orange)'
                          : 'var(--yellow)',
                    flexShrink: 0,
                  }}
                />
              )}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    fontSize: '13px',
                    fontWeight: 500,
                    color: 'var(--text-1)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {result.type === 'project' ? result.name : result.title}
                </div>
                <div
                  style={{
                    fontSize: '11px',
                    color: 'var(--text-3)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {result.type === 'project'
                    ? `${result.group} / ${result.provider}`
                    : `${result.file}${result.algorithm ? ` - ${result.algorithm}` : ''}`}
                </div>
              </div>
              <span
                style={{
                  fontSize: '10px',
                  color: 'var(--text-4)',
                  padding: '1px 6px',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                  flexShrink: 0,
                }}
              >
                {result.type === 'project' ? 'Project' : 'Finding'}
              </span>
            </div>
          ))}
        </div>

        {/* Footer hint */}
        <div
          style={{
            padding: '8px 16px',
            borderTop: '1px solid var(--border)',
            fontSize: '10px',
            color: 'var(--text-4)',
            display: 'flex',
            gap: '12px',
          }}
        >
          <span>
            <kbd style={{ padding: '1px 4px', border: '1px solid var(--border)', borderRadius: '3px', fontSize: '9px' }}>
              ↑↓
            </kbd>{' '}
            Navigate
          </span>
          <span>
            <kbd style={{ padding: '1px 4px', border: '1px solid var(--border)', borderRadius: '3px', fontSize: '9px' }}>
              Enter
            </kbd>{' '}
            Select
          </span>
          <span>
            <kbd style={{ padding: '1px 4px', border: '1px solid var(--border)', borderRadius: '3px', fontSize: '9px' }}>
              Esc
            </kbd>{' '}
            Close
          </span>
        </div>
      </div>
    </div>
  );
}
