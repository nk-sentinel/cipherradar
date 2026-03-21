import { useRef, useEffect, useState, useCallback, useMemo } from 'react';
import * as d3 from 'd3';
import { useGraph } from '@/api/hooks/useGraph.ts';
import type { GraphNode, GraphLink, QuantumNodeStatus, NodeType } from '@/mocks/data/graph.ts';

/* ---------- colour helpers ---------- */

function getCSSVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function quantumColor(status: QuantumNodeStatus): string {
  switch (status) {
    case 'safe':
      return 'var(--green)';
    case 'vulnerable':
      return 'var(--orange)';
    case 'broken':
      return 'var(--red)';
    case 'unknown':
      return 'var(--yellow)';
  }
}

function quantumHex(status: QuantumNodeStatus): string {
  switch (status) {
    case 'safe':
      return getCSSVar('--green');
    case 'vulnerable':
      return getCSSVar('--orange');
    case 'broken':
      return getCSSVar('--red');
    case 'unknown':
      return getCSSVar('--yellow');
  }
}

function nodeRadius(severity: string): number {
  switch (severity) {
    case 'critical':
      return 12;
    case 'high':
      return 10;
    case 'medium':
      return 8;
    case 'low':
      return 6;
    default:
      return 5;
  }
}

function typeShape(type: NodeType): string {
  switch (type) {
    case 'library':
      return 'square';
    case 'algorithm':
      return 'circle';
    case 'protocol':
      return 'diamond';
    case 'certificate':
      return 'triangle';
    case 'key':
      return 'star';
  }
}

/* ---------- simulation node type ---------- */

interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number | null;
  fy?: number | null;
}

interface SimLink {
  source: SimNode;
  target: SimNode;
  relationship: GraphLink['relationship'];
}

/* ---------- filter types ---------- */

const LANGUAGES = ['All', 'Java', 'Python', 'JavaScript', 'Kotlin', 'Go', 'TypeScript'];
const QUANTUM_STATUSES: { value: QuantumNodeStatus | ''; label: string }[] = [
  { value: '', label: 'All Status' },
  { value: 'safe', label: 'Safe' },
  { value: 'vulnerable', label: 'Vulnerable' },
  { value: 'broken', label: 'Broken' },
  { value: 'unknown', label: 'Unknown' },
];

/* ---------- component ---------- */

export function DependencyGraph(): React.ReactElement {
  const { data, isLoading, error } = useGraph();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const transformRef = useRef<d3.ZoomTransform>(d3.zoomIdentity);
  const linksRef = useRef<SimLink[]>([]);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [language, setLanguage] = useState('All');
  const [quantumStatus, setQuantumStatus] = useState('');
  const [dimensions, setDimensions] = useState({ width: 900, height: 600 });

  /* filter data */
  const filteredData = useMemo(() => {
    if (!data) return null;
    let nodes = data.nodes;
    if (language !== 'All') {
      nodes = nodes.filter((n) => n.language === language);
    }
    if (quantumStatus) {
      nodes = nodes.filter((n) => n.quantumStatus === quantumStatus);
    }
    const nodeIds = new Set(nodes.map((n) => n.id));
    const links = data.links.filter(
      (l) => nodeIds.has(l.source) && nodeIds.has(l.target),
    );
    return { nodes, links };
  }, [data, language, quantumStatus]);

  /* handle resize */
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const ro = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        setDimensions({
          width: entry.contentRect.width,
          height: Math.max(500, entry.contentRect.height),
        });
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  /* draw function */
  const draw = useCallback(
    (ctx: CanvasRenderingContext2D, nodes: SimNode[], links: SimLink[], transform: d3.ZoomTransform) => {
      const { width, height } = dimensions;

      /* resolve CSS variables inside draw so current theme is used */
      const labelColor = getCSSVar('--text-3');
      const selectionStroke = getCSSVar('--text-1');

      ctx.save();
      ctx.clearRect(0, 0, width, height);
      ctx.translate(transform.x, transform.y);
      ctx.scale(transform.k, transform.k);

      /* links */
      for (const link of links) {
        ctx.beginPath();
        ctx.moveTo(link.source.x, link.source.y);
        ctx.lineTo(link.target.x, link.target.y);
        ctx.strokeStyle = 'rgba(100, 120, 150, 0.25)';
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      /* nodes */
      for (const node of nodes) {
        const r = nodeRadius(node.severity);
        const color = quantumHex(node.quantumStatus);
        const shape = typeShape(node.type);
        const isSelected = selectedNode?.id === node.id;

        ctx.beginPath();
        if (shape === 'circle') {
          ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
        } else if (shape === 'square') {
          ctx.rect(node.x - r, node.y - r, r * 2, r * 2);
        } else if (shape === 'diamond') {
          ctx.moveTo(node.x, node.y - r * 1.2);
          ctx.lineTo(node.x + r, node.y);
          ctx.lineTo(node.x, node.y + r * 1.2);
          ctx.lineTo(node.x - r, node.y);
          ctx.closePath();
        } else if (shape === 'triangle') {
          ctx.moveTo(node.x, node.y - r * 1.2);
          ctx.lineTo(node.x + r, node.y + r * 0.8);
          ctx.lineTo(node.x - r, node.y + r * 0.8);
          ctx.closePath();
        } else {
          // star for key
          for (let i = 0; i < 5; i++) {
            const outerAngle = ((Math.PI * 2 * i) / 5) - Math.PI / 2;
            const innerAngle = outerAngle + Math.PI / 5;
            const ox = node.x + Math.cos(outerAngle) * r * 1.2;
            const oy = node.y + Math.sin(outerAngle) * r * 1.2;
            const ix = node.x + Math.cos(innerAngle) * r * 0.5;
            const iy = node.y + Math.sin(innerAngle) * r * 0.5;
            if (i === 0) {
              ctx.moveTo(ox, oy);
            } else {
              ctx.lineTo(ox, oy);
            }
            ctx.lineTo(ix, iy);
          }
          ctx.closePath();
        }

        ctx.fillStyle = color;
        ctx.globalAlpha = isSelected ? 1 : 0.85;
        ctx.fill();

        if (isSelected) {
          ctx.strokeStyle = selectionStroke;
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        ctx.globalAlpha = 1;

        /* label for larger nodes or when zoomed in */
        if (r >= 8 || transform.k > 1.2) {
          ctx.fillStyle = labelColor;
          ctx.font = '9px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(node.label, node.x, node.y + r + 12);
        }
      }

      ctx.restore();
    },
    [dimensions, selectedNode],
  );

  /* setup simulation */
  useEffect(() => {
    if (!filteredData || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { width, height } = dimensions;
    canvas.width = width;
    canvas.height = height;

    const nodeMap = new Map<string, SimNode>();
    const simNodes: SimNode[] = filteredData.nodes.map((n) => {
      const simNode: SimNode = { ...n, x: Math.random() * width, y: Math.random() * height, vx: 0, vy: 0 };
      nodeMap.set(n.id, simNode);
      return simNode;
    });
    const simLinks: SimLink[] = [];
    for (const link of filteredData.links) {
      const source = nodeMap.get(link.source);
      const target = nodeMap.get(link.target);
      if (source && target) {
        simLinks.push({ source, target, relationship: link.relationship });
      }
    }
    linksRef.current = simLinks;

    const simulation = d3
      .forceSimulation<SimNode>(simNodes)
      .force(
        'charge',
        d3.forceManyBody<SimNode>().strength(-30),
      )
      .force(
        'link',
        d3.forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.id)
          .distance(60),
      )
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide<SimNode>().radius((d) => nodeRadius(d.severity) + 2))
      .alphaDecay(0.02);

    simulation.on('tick', () => {
      draw(ctx, simNodes, simLinks, transformRef.current);
    });

    /* zoom/pan */
    const zoomBehavior = d3
      .zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.2, 5])
      .on('zoom', (event: d3.D3ZoomEvent<HTMLCanvasElement, unknown>) => {
        transformRef.current = event.transform;
        draw(ctx, simNodes, simLinks, event.transform);
      });

    const canvasSelection = d3.select(canvas);
    canvasSelection.call(zoomBehavior);

    /* click handling */
    const handleClick = (event: MouseEvent) => {
      const [mx, my] = d3.pointer(event, canvas);
      const transform = transformRef.current;
      const x = (mx - transform.x) / transform.k;
      const y = (my - transform.y) / transform.k;

      let closest: SimNode | null = null;
      let closestDist = Infinity;
      for (const node of simNodes) {
        const r = nodeRadius(node.severity) + 4;
        const dx = node.x - x;
        const dy = node.y - y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < r && dist < closestDist) {
          closest = node;
          closestDist = dist;
        }
      }
      setSelectedNode(closest);
    };
    canvas.addEventListener('click', handleClick);

    return () => {
      simulation.stop();
      canvasSelection.on('.zoom', null);
      canvas.removeEventListener('click', handleClick);
    };
  }, [filteredData, dimensions, draw]);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load dependency graph data.
        </p>
      </div>
    );
  }

  const nodeCount = filteredData?.nodes.length ?? 0;
  const linkCount = filteredData?.links.length ?? 0;

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
          Crypto Dependency Graph
        </h1>
        <div className="topbar-right">
          <span style={{ color: 'var(--text-3)', fontSize: '11px' }}>
            {nodeCount} nodes / {linkCount} edges
          </span>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
        <select
          className="filter"
          value={language}
          onChange={(e) => setLanguage(e.target.value)}
          aria-label="Filter by language"
        >
          {LANGUAGES.map((l) => (
            <option key={l} value={l}>{l === 'All' ? 'All Languages' : l}</option>
          ))}
        </select>
        <select
          className="filter"
          value={quantumStatus}
          onChange={(e) => setQuantumStatus(e.target.value)}
          aria-label="Filter by quantum status"
        >
          {QUANTUM_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
      </div>

      {/* Legend */}
      <div
        className="card"
        style={{
          display: 'flex',
          gap: '20px',
          flexWrap: 'wrap',
          padding: '10px 16px',
          marginBottom: '12px',
        }}
      >
        <div style={{ fontSize: '10px', color: 'var(--text-3)', fontWeight: 600 }}>QUANTUM STATUS:</div>
        {(['safe', 'vulnerable', 'broken', 'unknown'] as QuantumNodeStatus[]).map((s) => (
          <div key={s} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: quantumColor(s) }} />
            <span style={{ textTransform: 'capitalize' }}>{s}</span>
          </div>
        ))}
        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: '12px', fontSize: '10px', color: 'var(--text-3)', fontWeight: 600 }}>
          NODE TYPE:
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-2)' }}>Circle=Algorithm, Square=Library, Diamond=Protocol, Triangle=Cert, Star=Key</span>
      </div>

      <div className="g2">
        {/* Canvas */}
        <div
          ref={containerRef}
          className="card"
          style={{ padding: '0', overflow: 'hidden', minHeight: '500px', position: 'relative' }}
        >
          <canvas
            ref={canvasRef}
            style={{ display: 'block', width: '100%', height: '100%', cursor: 'grab' }}
          />
        </div>

        {/* Detail panel */}
        <div className="card" style={{ minHeight: '500px' }}>
          <div className="card-title">Node Detail</div>
          {selectedNode ? (
            <div>
              <div style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px' }}>
                {selectedNode.label}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <DetailRow label="Type" value={selectedNode.type} />
                <DetailRow label="Language" value={selectedNode.language} />
                <DetailRow label="Repository" value={selectedNode.repository} />
                <DetailRow label="File" value={`${selectedNode.file}:${String(selectedNode.line)}`} />
                <DetailRow label="Severity" value={selectedNode.severity} />
                <div>
                  <div className="field-label">Quantum Status</div>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius)',
                      fontSize: '11px',
                      fontWeight: 600,
                      background: quantumColor(selectedNode.quantumStatus),
                      color: selectedNode.quantumStatus === 'safe' || selectedNode.quantumStatus === 'unknown' ? 'var(--bg-0)' : 'var(--text-1)',
                    }}
                  >
                    {selectedNode.quantumStatus.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Connected nodes */}
              <div style={{ marginTop: '20px' }}>
                <div className="card-title">Connected Nodes</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {linksRef.current
                    .filter(
                      (l) =>
                        l.source.id === selectedNode.id ||
                        l.target.id === selectedNode.id,
                    )
                    .slice(0, 10)
                    .map((l, i) => {
                      const other =
                        l.source.id === selectedNode.id ? l.target : l.source;
                      return (
                        <div
                          key={i}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            fontSize: '11px',
                            padding: '4px 0',
                            borderBottom: '1px solid var(--border-light)',
                            cursor: 'pointer',
                          }}
                          onClick={() => setSelectedNode(other)}
                        >
                          <div
                            style={{
                              width: '8px',
                              height: '8px',
                              borderRadius: '50%',
                              background: quantumColor(other.quantumStatus),
                              flexShrink: 0,
                            }}
                          />
                          <span style={{ color: 'var(--accent)' }}>{other.label}</span>
                          <span style={{ color: 'var(--text-4)' }}>({l.relationship})</span>
                        </div>
                      );
                    })}
                </div>
              </div>
            </div>
          ) : (
            <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
              Click a node in the graph to view details.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <div>
      <div className="field-label">{label}</div>
      <div style={{ fontSize: '12px', textTransform: 'capitalize' }}>{value}</div>
    </div>
  );
}
