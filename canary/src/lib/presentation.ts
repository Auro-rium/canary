export const pageClass = 'min-h-screen bg-black text-white font-mono pt-24'

export function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

export function formatDuration(milliseconds: number) {
  return milliseconds >= 1000 ? `${(milliseconds / 1000).toFixed(1)}s` : `${milliseconds.toFixed(0)}ms`
}

export function strategyLabel(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}
