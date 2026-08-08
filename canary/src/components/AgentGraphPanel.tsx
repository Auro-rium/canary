import type { Phase, AgentStatus } from '../lib/types'

const NODE_R = 32

type TopoNode = {
  cx: number
  cy: number
  label: string
  color: string
  rect?: { w: number; h: number }
  abbrev?: string
}

const TOPO_NODES: Record<string, TopoNode> = {
  orchestrator: { cx: 400, cy: 55,  label: 'ORCHESTRATOR',   color: '#ffffff', abbrev: 'ORC' },
  strategist:   { cx: 150, cy: 165, label: 'STRATEGIST',     color: '#a78bfa', abbrev: 'STR' },
  evaluator:    { cx: 400, cy: 165, label: 'EVALUATOR',      color: '#60a5fa', abbrev: 'EVL' },
  attacker:     { cx: 150, cy: 310, label: 'ATTACKER',       color: '#ef4444', abbrev: 'ATK' },
  target:       { cx: 400, cy: 310, label: 'TARGET',         color: '#f59e0b', rect: { w: 90, h: 36 } },
  reporter:     { cx: 650, cy: 310, label: 'REPORTER',       color: '#c084fc', abbrev: 'RPT' },
  findings:     { cx: 400, cy: 440, label: 'FINDINGS STORE', color: '#6b7280', rect: { w: 110, h: 28 } },
}

const TOPO_EDGES: { from: string; to: string }[] = [
  { from: 'orchestrator', to: 'strategist' },
  { from: 'orchestrator', to: 'evaluator' },
  { from: 'strategist',   to: 'attacker' },
  { from: 'attacker',     to: 'target' },
  { from: 'evaluator',    to: 'target' },
  { from: 'evaluator',    to: 'findings' },
  { from: 'evaluator',    to: 'reporter' },
  { from: 'reporter',     to: 'findings' },
]

const STATUS_COLORS: Record<AgentStatus, string> = {
  idle:       'rgba(255,255,255,0.2)',
  active:     'rgba(255,255,255,0.85)',
  processing: '#ef4444',
  done:       'rgba(255,255,255,0.35)',
  error:      '#ef4444',
}

const ARROW_IDS: Record<string, string> = {
  '#ffffff': 'arr-ffffff',
  '#a78bfa': 'arr-a78bfa',
  '#60a5fa': 'arr-60a5fa',
  '#34d399': 'arr-34d399',
  '#ef4444': 'arr-ef4444',
  '#f59e0b': 'arr-f59e0b',
  '#c084fc': 'arr-c084fc',
  '#6b7280': 'arr-6b7280',
}

function getNodeEndpoints(fromId: string, toId: string): { sx: number; sy: number; ex: number; ey: number } {
  const from = TOPO_NODES[fromId]
  const to   = TOPO_NODES[toId]
  const dx   = to.cx - from.cx
  const dy   = to.cy - from.cy
  const dist = Math.sqrt(dx * dx + dy * dy) || 1
  const ux   = dx / dist
  const uy   = dy / dist

  let sx: number, sy: number
  if (from.rect) {
    const { w, h } = from.rect
    const tx = ux !== 0 ? (w / 2) / Math.abs(ux) : Infinity
    const ty = uy !== 0 ? (h / 2) / Math.abs(uy) : Infinity
    const t  = Math.min(tx, ty)
    sx = from.cx + ux * t
    sy = from.cy + uy * t
  } else {
    sx = from.cx + ux * NODE_R
    sy = from.cy + uy * NODE_R
  }

  let ex: number, ey: number
  if (to.rect) {
    const { w, h } = to.rect
    const tx = ux !== 0 ? (w / 2) / Math.abs(ux) : Infinity
    const ty = uy !== 0 ? (h / 2) / Math.abs(uy) : Infinity
    const t  = Math.min(tx, ty)
    ex = to.cx - ux * t
    ey = to.cy - uy * t
  } else {
    ex = to.cx - ux * NODE_R
    ey = to.cy - uy * NODE_R
  }

  return { sx, sy, ex, ey }
}

function buildEdgePath(fromId: string, toId: string): string {
  // evaluator→findings is routed as a curve so it doesn't cross through the target node
  if (fromId === 'evaluator' && toId === 'findings') {
    const evalNode = TOPO_NODES.evaluator
    const findNode = TOPO_NODES.findings
    const sx = evalNode.cx
    const sy = evalNode.cy + NODE_R
    const ex = findNode.cx
    const ey = findNode.cy - findNode.rect!.h / 2
    return `M ${sx} ${sy} C 490 280 490 400 ${ex} ${ey}`
  }
  const { sx, sy, ex, ey } = getNodeEndpoints(fromId, toId)
  return `M ${sx} ${sy} L ${ex} ${ey}`
}

interface AgentGraphPanelProps {
  phase: Phase
  statuses: Record<string, AgentStatus>
  activeEdge: string | null
}

export default function AgentGraphPanel({ phase, statuses, activeEdge }: AgentGraphPanelProps) {
  const nodeIds = Object.keys(TOPO_NODES)

  return (
    <svg viewBox="0 0 800 520" className="w-full h-full" style={{ display: 'block', minHeight: 500 }}>
      <defs>
        <filter id="node-glow" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="6" result="blur" in="SourceGraphic" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        {[
          ['arr-inactive', 'rgba(255,255,255,0.1)'],
          ['arr-ffffff', '#ffffff'],
          ['arr-a78bfa', '#a78bfa'],
          ['arr-60a5fa', '#60a5fa'],
          ['arr-34d399', '#34d399'],
          ['arr-ef4444', '#ef4444'],
          ['arr-f59e0b', '#f59e0b'],
          ['arr-c084fc', '#c084fc'],
          ['arr-6b7280', '#6b7280'],
        ].map(([id, color]) => (
          <marker key={id} id={id} markerWidth={8} markerHeight={7} refX={8} refY={3.5} orient="auto" markerUnits="userSpaceOnUse">
            <path d="M 0 0 L 8 3.5 L 0 7 Z" fill={color} />
          </marker>
        ))}
      </defs>

      {/* Edges */}
      {TOPO_EDGES.map(({ from, to }) => {
        const edgeKey   = `${from}->${to}`
        const isActive  = activeEdge === edgeKey
        const srcColor  = TOPO_NODES[from]?.color ?? '#ffffff'
        const markerId  = isActive ? (ARROW_IDS[srcColor] ?? 'arr-inactive') : 'arr-inactive'
        const edgePath  = buildEdgePath(from, to)

        return (
          <g key={edgeKey} opacity={phase === 'idle' ? 0.4 : 1}>
            <path
              d={edgePath}
              fill="none"
              stroke={isActive ? srcColor : 'rgba(255,255,255,0.08)'}
              strokeWidth={isActive ? 1.5 : 1}
              markerEnd={`url(#${markerId})`}
            />
            {isActive && (
              <circle r={4} fill={srcColor} opacity={0.9}>
                <animateMotion dur="1.2s" repeatCount="indefinite" path={edgePath} />
              </circle>
            )}
          </g>
        )
      })}

      {/* Nodes */}
      {nodeIds.map(id => {
        const node = TOPO_NODES[id]
        const status: AgentStatus = statuses[id] ?? 'idle'
        const isActive     = status === 'active'
        const isProcessing = status === 'processing'
        const isDone       = status === 'done'
        const isLit        = isActive || isProcessing
        const { cx, cy, label, color, rect, abbrev } = node
        const strokeColor = isLit ? color : isDone ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.15)'
        const fillColor   = isLit ? `${color}1A` : '#000000'
        const statusColor = STATUS_COLORS[status]
        const labelY  = rect ? cy + rect.h / 2 + 14 : cy + NODE_R + 14
        const statusY = rect ? cy + rect.h / 2 + 26 : cy + NODE_R + 26

        return (
          <g key={id} opacity={phase === 'idle' ? 0.35 : 1}>
            {isProcessing && !rect && (
              <circle cx={cx} cy={cy} r={NODE_R + 10} fill="none" stroke={color} strokeOpacity={0.55} strokeWidth={1.5} strokeDasharray="20 10">
                <animateTransform attributeName="transform" type="rotate" from={`0 ${cx} ${cy}`} to={`360 ${cx} ${cy}`} dur="2.5s" repeatCount="indefinite" />
              </circle>
            )}

            {rect ? (
              <rect
                x={cx - rect.w / 2} y={cy - rect.h / 2}
                width={rect.w} height={rect.h}
                fill={fillColor}
                stroke={strokeColor}
                strokeWidth={isLit ? 1.5 : 1}
                strokeDasharray={id === 'target' ? '5 3' : '0'}
                filter={isLit ? 'url(#node-glow)' : undefined}
              />
            ) : (
              <circle
                cx={cx} cy={cy} r={NODE_R}
                fill={fillColor}
                stroke={strokeColor}
                strokeWidth={1.5}
                filter={isLit ? 'url(#node-glow)' : undefined}
              />
            )}

            {isDone && !rect && (
              <path
                d={`M ${cx - 9} ${cy} L ${cx - 3} ${cy + 7} L ${cx + 10} ${cy - 8}`}
                fill="none" stroke="rgba(255,255,255,0.45)" strokeWidth={1.5} strokeLinecap="round"
              />
            )}

            {!isDone && !rect && abbrev && (
              <text x={cx} y={cy + 3} textAnchor="middle" fontSize={8} fontFamily="'JetBrains Mono', monospace" fontWeight="bold" fill={isLit ? color : 'rgba(255,255,255,0.35)'}>
                {abbrev}
              </text>
            )}

            {rect && (
              <text x={cx} y={cy + 3} textAnchor="middle" fontSize={9} fontFamily="'JetBrains Mono', monospace" fill={isLit ? color : 'rgba(255,255,255,0.6)'}>
                {label}
              </text>
            )}

            {!rect && (
              <text x={cx} y={labelY} textAnchor="middle" fontSize={9} fontFamily="'JetBrains Mono', monospace" fill="rgba(255,255,255,0.7)">
                {label}
              </text>
            )}

            <circle cx={cx - 22} cy={statusY - 2} r={2.5} fill={statusColor} />
            <text x={cx - 16} y={statusY + 1} fontSize={7} fontFamily="'JetBrains Mono', monospace" fill={statusColor}>
              {status.toUpperCase()}
            </text>
          </g>
        )
      })}

      {phase === 'idle' && (
        <text x={400} y={485} textAnchor="middle" fontSize={11} fontFamily="'JetBrains Mono', monospace" fill="rgba(255,255,255,0.15)" letterSpacing={3}>
          AWAITING CAMPAIGN
        </text>
      )}
    </svg>
  )
}
