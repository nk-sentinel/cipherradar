import { useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/api/client.ts';
import { cn } from '@/lib/utils.ts';
import type {
  KanbanCard,
  KanbanColumnId,
  KanbanPriority,
} from '@/mocks/data/kanban.ts';

const COLUMN_DEFS: { id: KanbanColumnId; title: string }[] = [
  { id: 'todo', title: 'To Do' },
  { id: 'in-progress', title: 'In Progress' },
  { id: 'in-review', title: 'In Review' },
  { id: 'done', title: 'Done' },
];

function useKanbanCards() {
  return useQuery({
    queryKey: ['kanban'],
    queryFn: async () => {
      try {
        return await apiClient<KanbanCard[]>('/kanban');
      } catch {
        if (import.meta.env.DEV) {
          const { getKanbanCards } = await import('@/mocks/data/kanban.ts');
          return getKanbanCards();
        }
        throw new Error('Failed to fetch kanban cards');
      }
    },
    staleTime: 30_000,
  });
}

function priorityBadgeClass(p: KanbanPriority): string {
  switch (p) {
    case 'critical':
      return 'b-crit';
    case 'high':
      return 'b-high';
    case 'medium':
      return 'b-med';
    case 'low':
      return 'b-safe';
  }
}

function priorityLabel(p: KanbanPriority): string {
  switch (p) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
  }
}

export function MigrationKanban(): React.ReactElement {
  const { data: cards, isLoading, error } = useKanbanCards();
  const [localCards, setLocalCards] = useState<KanbanCard[] | null>(null);
  const [selectedCard, setSelectedCard] = useState<KanbanCard | null>(null);
  const [dragOverColumn, setDragOverColumn] = useState<KanbanColumnId | null>(null);
  const [filterRepo, setFilterRepo] = useState<string>('');
  const [filterLanguage, setFilterLanguage] = useState<string>('');
  const [filterFramework, setFilterFramework] = useState<string>('');

  // Use local state once cards are loaded (for drag-and-drop reordering)
  const activeCards = localCards ?? cards ?? [];

  // Sync loaded cards into local state
  const ensureLocalCards = useCallback(() => {
    if (!localCards && cards) {
      setLocalCards([...cards]);
    }
  }, [localCards, cards]);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error || !cards) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load migration board.
        </p>
      </div>
    );
  }

  // Extract unique filter values
  const repos = [...new Set(activeCards.map((c) => c.repo))];
  const languages = [...new Set(activeCards.map((c) => c.language))];
  const frameworks = [...new Set(activeCards.map((c) => c.framework))];

  // Apply filters
  let filteredCards = activeCards;
  if (filterRepo) {
    filteredCards = filteredCards.filter((c) => c.repo === filterRepo);
  }
  if (filterLanguage) {
    filteredCards = filteredCards.filter((c) => c.language === filterLanguage);
  }
  if (filterFramework) {
    filteredCards = filteredCards.filter((c) => c.framework === filterFramework);
  }

  const handleDragStart = (e: React.DragEvent<HTMLDivElement>, card: KanbanCard) => {
    ensureLocalCards();
    e.dataTransfer.setData('text/plain', card.id);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>, columnId: KanbanColumnId) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOverColumn(columnId);
  };

  const handleDragLeave = () => {
    setDragOverColumn(null);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>, columnId: KanbanColumnId) => {
    e.preventDefault();
    setDragOverColumn(null);
    const cardId = e.dataTransfer.getData('text/plain');
    if (!cardId) return;

    setLocalCards((prev) => {
      const source = prev ?? cards ?? [];
      return source.map((c) =>
        c.id === cardId ? { ...c, column: columnId } : c,
      );
    });
  };

  return (
    <div>
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
          Migration Kanban
        </h1>
      </div>

      {/* Filters */}
      <div
        className="filters"
        style={{ marginBottom: '16px', gap: '8px', display: 'flex', flexWrap: 'wrap' }}
      >
        <select
          className="input"
          style={{ width: 'auto', minWidth: '140px' }}
          value={filterRepo}
          onChange={(e) => setFilterRepo(e.target.value)}
          aria-label="Filter by repo"
        >
          <option value="">All Repos</option>
          {repos.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <select
          className="input"
          style={{ width: 'auto', minWidth: '140px' }}
          value={filterLanguage}
          onChange={(e) => setFilterLanguage(e.target.value)}
          aria-label="Filter by language"
        >
          <option value="">All Languages</option>
          {languages.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
        <select
          className="input"
          style={{ width: 'auto', minWidth: '140px' }}
          value={filterFramework}
          onChange={(e) => setFilterFramework(e.target.value)}
          aria-label="Filter by framework"
        >
          <option value="">All Frameworks</option>
          {frameworks.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </div>

      {/* Kanban board */}
      <div
        className="kanban-grid"
        style={{
          minHeight: '500px',
        }}
        data-testid="kanban-board"
      >
        {COLUMN_DEFS.map((col) => {
          const columnCards = filteredCards.filter((c) => c.column === col.id);
          return (
            <div
              key={col.id}
              data-testid={`column-${col.id}`}
              onDragOver={(e) => handleDragOver(e, col.id)}
              onDragLeave={handleDragLeave}
              onDrop={(e) => handleDrop(e, col.id)}
              style={{
                background: dragOverColumn === col.id ? 'var(--accent-dim)' : 'var(--bg-1)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '12px',
                minHeight: '200px',
                transition: 'background 0.15s',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '12px',
                }}
              >
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    color: 'var(--text-3)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}
                >
                  {col.title}
                </span>
                <span
                  className="badge"
                  style={{
                    background: 'var(--bg-3)',
                    color: 'var(--text-3)',
                    fontSize: '10px',
                  }}
                >
                  {columnCards.length}
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {columnCards.map((card) => (
                  <KanbanCardComponent
                    key={card.id}
                    card={card}
                    onDragStart={handleDragStart}
                    onClick={() => setSelectedCard(card)}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Card detail modal */}
      {selectedCard && (
        <CardDetailModal card={selectedCard} onClose={() => setSelectedCard(null)} />
      )}
    </div>
  );
}

function KanbanCardComponent({
  card,
  onDragStart,
  onClick,
}: {
  card: KanbanCard;
  onDragStart: (e: React.DragEvent<HTMLDivElement>, card: KanbanCard) => void;
  onClick: () => void;
}): React.ReactElement {
  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, card)}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick();
        }
      }}
      style={{
        background: 'var(--bg-2)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '10px',
        cursor: 'grab',
        transition: 'border-color 0.12s',
      }}
      data-testid={`card-${card.id}`}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '6px',
        }}
      >
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-1)' }}>
          {card.findingName}
        </span>
        <span className={cn('badge', priorityBadgeClass(card.priority))}>
          {priorityLabel(card.priority)}
        </span>
      </div>
      <div style={{ fontSize: '10px', color: 'var(--text-3)', marginBottom: '4px' }}>
        {card.repo}
      </div>
      <div style={{ fontSize: '10px', color: 'var(--text-4)', marginBottom: '6px' }}>
        {card.currentAlgorithm} → {card.recommendedReplacement}
      </div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '10px',
        }}
      >
        <span style={{ color: 'var(--text-3)' }}>{card.assignee}</span>
        <span style={{ color: 'var(--text-4)' }}>{card.deadline}</span>
      </div>
    </div>
  );
}

function CardDetailModal({
  card,
  onClose,
}: {
  card: KanbanCard;
  onClose: () => void;
}): React.ReactElement {
  return (
    <div
      data-testid="card-detail-modal"
      onClick={onClose}
      onKeyDown={(e) => {
        if (e.key === 'Escape') onClose();
      }}
      role="dialog"
      aria-label={`Details for ${card.findingName}`}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 200,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--bg-2)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          padding: '24px',
          width: '520px',
          maxHeight: '80vh',
          overflowY: 'auto',
          boxShadow: '0 12px 40px rgba(0, 0, 0, 0.4)',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            marginBottom: '16px',
          }}
        >
          <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-1)' }}>
            {card.findingName}
          </h2>
          <button
            onClick={onClose}
            className="btn btn-outline"
            style={{ padding: '4px 8px', fontSize: '10px' }}
            aria-label="Close"
          >
            X
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
          <DetailField label="Repository" value={card.repo} />
          <DetailField label="Language" value={card.language} />
          <DetailField label="Framework" value={card.framework} />
          <DetailField label="Assignee" value={card.assignee} />
          <DetailField label="Current Algorithm" value={card.currentAlgorithm} />
          <DetailField label="Recommended Replacement" value={card.recommendedReplacement} />
          <DetailField label="Deadline" value={card.deadline} />
          <DetailField label="CNSA 2.0 Deadline" value={card.cnsa20Deadline} />
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: 'var(--text-3)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: '4px',
            }}
          >
            Priority
          </div>
          <span className={cn('badge', priorityBadgeClass(card.priority))}>
            {priorityLabel(card.priority)}
          </span>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: 'var(--text-3)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: '4px',
            }}
          >
            Replacement Guidance
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-2)', lineHeight: '1.6' }}>
            {card.replacementGuidance}
          </p>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div
            style={{
              fontSize: '10px',
              fontWeight: 600,
              color: 'var(--text-3)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: '4px',
            }}
          >
            Finding Link
          </div>
          <a
            href={card.findingLink}
            style={{ fontSize: '12px', color: 'var(--accent)' }}
          >
            View Finding
          </a>
        </div>
      </div>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div>
      <div
        style={{
          fontSize: '10px',
          fontWeight: 600,
          color: 'var(--text-3)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginBottom: '2px',
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-1)' }}>{value}</div>
    </div>
  );
}
