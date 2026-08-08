import type { Phase, AgentStatus } from '../lib/types'

const NODE_R = 32
type TopoNode = { cx: number; cy: number; label: string; color: string; rect?: { w: number; h: number }; abbrev?: string }
const TOPO_NODES: Record<string, TopoNode> = {
  orchestrator: { cx: 400, cy: 55, label: 'ORCHESTRATOR', color: '#ffffff', abbrev: 'ORC' },
  strategist: { cx: 150, cy: 165, label: 'STRATEGIST', color: '#a78bfa', abbrev: 'STR' },
  evaluator: { cx: 400, cy: 165, label: 'EVALUATOR', color: '#60a5fa', abbrev: 'EVL' },
  attacker: { cx: 150, cy: 310, label: 'ATTACKER', color: '#ef4444', abbrev: 'ATK' },
  target: { cx: 400, cy: 310, label: 'TARGET', color: '#f59e0b', rect: { w: 90, h: 36 } },
  reporter: { cx: 650, cy: 310, label: 'REPORTER', color: '#c084fc', abbrev: 'RPT' },
  findings: { cx: 400, cy: 440, label: 'FINDINGS STORE', color: '#6b7280', rect: { w: 110, h: 28 } },
}
const TOPO_EDGES = [
  ['orchestrator', 'strategist'], ['orchestrator', 'evaluator'], ['strategist', 'attacker'],
  ['attacker', 'target'], ['evaluator', 'target'], ['evaluator', 'findings'],
  ['evaluator', 'reporter'], ['reporter', 'findings'],
] as const
const STATUS_COLORS: Record<AgentStatus, string> = {
  idle: 'rgba(255,255,255,0.2)', active: 'rgba(255,255,255,0.85)', processing: '#ef4444', done: 'rgba(255,255,255,0.35)', error: '#ef4444',
}
const ARROW_IDS: Record<string, string> = {
  '#ffffff': 'arr-ffffff', '#a78bfa': 'arr-a78bfa', '#60a5fa': 'arr-60a5fa', '#ef4444': 'arr-ef4444',
  '#f59e0b': 'arr-f59e0b', '#c084fc': 'arr-c084fc', '#6b7280': 'arr-6b7280',
}

function endpoints(fromId: string, toId: string) {
  const from = TOPO_NODES[fromId], to = TOPO_NODES[toId]
  const dx = to.cx - from.cx, dy = to.cy - from.cy, dist = Math.sqrt(dx * dx + dy * dy) || 1
  const ux = dx / dist, uy = dy / dist
  const point = (node: TopoNode, sign: number) => {
    if (node.rect) {
      const tx = ux !== 0 ? (node.rect.w / 2) / Math.abs(ux) : Infinity
      const ty = uy !== 0 ? (node.rect.h / 2) / Math.abs(uy) : Infinity
      const t = Math.min(tx, ty)
      return { x: node.cx + sign * ux * t, y: node.cy + sign * uy * t }
    }
    return { x: node.cx + sign * ux * NODE_R, y: node.cy + sign * uy * NODE_R }
  }
  const s = point(from, 1), e = point(to, -1)
  return { sx: s.x, sy: s.y, ex: e.x, ey: e.y }
}

function edgePath(fromId: string, toId: string) {
  if (fromId === 'evaluator' && toId === 'findings') return 'M 400 197 C 490 280 490 400 400 426'
  const { sx, sy, ex, ey } = endpoints(fromId, toId)
  return `M ${sx} ${sy} L ${ex} ${ey}`
}

interface AgentGraphPanelProps { phase: Phase; statuses: Record<string, AgentStatus>; activeEdge: string | null }

export default function AgentGraphPanel({ phase, statuses, activeEdge }: AgentGraphPanelProps) {
  return (
    <svg viewBox="0 0 800 520" className="w-full h-full" style={{ display: 'block', minHeight: 500 }}>
      <defs>
        <filter id="node-glow" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="6" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        {[['arr-inactive', 'rgba(255,255,255,0.1)'], ['arr-ffffff', '#ffffff'], ['arr-a78bfa', '#a78bfa'], ['arr-60a5fa', '#60a5fa'], ['arr-ef4444', '#ef4444'], ['arr-f59e0b', '#f59e0b'], ['arr-c084fc', '#c084fc'], ['arr-6b7280', '#6b7280']].map(([id, color]) => (
          <marker key={id} id={id} markerWidth={8} markerHeight={7} refX={8} refY={3.5} orient="auto" markerUnits="userSpaceOnUse"><path d="M 0 0 L 8 3.5 L 0 7 Z" fill={color} /></marker>
        ))}
      </defs>
      {TOPO_EDGES.map(([from, to]) => {
        const key = `${from}->${to}`, active = activeEdge === key, color = TOPO_NODES[from].color
        const path = edgePath(from, to)
        return <g key={key} opacity={phase === 'idle' ? 0.4 : 1}><path d={path} fill="none" stroke={active ? color : 'rgba(255,255,255,0.08)'} strokeWidth={active ? 1.5 : 1} markerEnd={`url(#${active ? (ARROW_IDS[color] ?? 'arr-inactive') : 'arr-inactive'})`} />{active && <circle r={4} fill={color} opacity={0.9}><animateMotion dur="1.2s" repeatCount="indefinite" path={path} /></circle>}</g>
      })}
      {Object.entries(TOPO_NODES).map(([id, node]) => {
        const status = statuses[id] ?? 'idle', lit = status === 'active' || status === 'processing', done = status === 'done', rect = node.rect
        const stroke = lit ? node.color : done ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.15)'
        const fill = lit ? `${node.color}1A` : '#000000', labelY = rect ? node.cy + rect.h / 2 + 14 : node.cy + NODE_R + 14, statusY = rect ? node.cy + rect.h / 2 + 26 : node.cy + NODE_R + 26
        return <g key={id} opacity={phase === 'idle' ? 0.35 : 1}>
          {status === 'processing' && !rect && <circle cx={node.cx} cy={node.cy} r={NODE_R + 10} fill="none" stroke={node.color} strokeOpacity={0.55} strokeWidth={1.5} strokeDasharray="20 10"><animateTransform attributeName="transform" type="rotate" from={`0 ${node.cx} ${node.cy}`} to={`360 ${node.cx} ${node.cy}`} dur="2.5s" repeatCount="indefinite" /></circle>}
          {rect ? <rect x={node.cx - rect.w / 2} y={node.cy - rect.h / 2} width={rect.w} height={rect.h} fill={fill} stroke={stroke} strokeWidth={lit ? 1.5 : 1} strokeDasharray={id === 'target' ? '5 3' : '0'} filter={lit ? 'url(#node-glow)' : undefined} /> : <circle cx={node.cx} cy={node.cy} r={NODE_R} fill={fill} stroke={stroke} strokeWidth={1.5} filter={lit ? 'url(#node-glow)' : undefined} />}
          {done && !rect && <path d={`M ${node.cx - 9} ${node.cy} L ${node.cx - 3} ${node.cy + 7} L ${node.cx + 10} ${node.cy - 8}`} fill="none" stroke="rgba(255,255,255,0.45)" strokeWidth={1.5} strokeLinecap="round" />}
          {!done && !rect && node.abbrev && <text x={node.cx} y={node.cy + 3} textAnchor="middle" fontSize={8} fontFamily="'JetBrains Mono', monospace" fontWeight="bold" fill={lit ? node.color : 'rgba(255,255,255,0.35)'}>{node.abbrev}</text>}
          {rect && <text x={node.cx} y={node.cy + 3} textAnchor="middle" fontSize={9} fontFamily="'JetBrains Mono', monospace" fill={lit ? node.color : 'rgba(255,255,255,0.6)'}>{node.label}</text>}
          {!rect && <text x={node.cx} y={labelY} textAnchor="middle" fontSize={9} fontFamily="'JetBrains Mono', monospace" fill="rgba(255,255,255,0.7)">{node.label}</text>}
          <circle cx={node.cx - 22} cy={statusY - 2} r={2.5} fill={STATUS_COLORS[status]} /><text x={node.cx - 16} y={statusY + 1} fontSize={7} fontFamily="'JetBrains Mono', monospace" fill={STATUS_COLORS[status]}>{status.toUpperCase()}</text>
        </g>
      })}
      {phase === 'idle' && <text x={400} y={485} textAnchor="middle" fontSize={11} fontFamily="'JetBrains Mono', monospace" fill="rgba(255,255,255,0.15)" letterSpacing={3}>AWAITING CAMPAIGN</text>}
    </svg>
  )
}
