import { describe, expect, it } from 'vitest'
import { ciGeometry, pct } from '../components/ui/CIBar'
import { splitRedactions } from '../components/ui/CodeBlock'
import { meterState } from '../components/ui/Meter'
import { nextSort, pageRange, sortRows, type Column } from '../components/ui/Table'
import { resolveTheme } from './theme'

interface Row { name: string; rate: number | null }
const columns: Column<Row>[] = [
  { key: 'name', header: 'Name', cell: r => r.name, sortValue: r => r.name },
  { key: 'rate', header: 'Rate', cell: r => String(r.rate), sortValue: r => r.rate },
  { key: 'plain', header: 'Plain', cell: () => '' },
]
const rows: Row[] = [{ name: 'b', rate: 0.5 }, { name: 'a', rate: null }, { name: 'c', rate: 0.1 }]

describe('Table sorting', () => {
  it('cycles asc, desc, none per column and restarts on a new column', () => {
    const asc = nextSort(null, 'name')
    expect(asc).toEqual({ key: 'name', dir: 'asc' })
    expect(nextSort(asc, 'name')).toEqual({ key: 'name', dir: 'desc' })
    expect(nextSort({ key: 'name', dir: 'desc' }, 'name')).toBeNull()
    expect(nextSort(asc, 'rate')).toEqual({ key: 'rate', dir: 'asc' })
  })
  it('sorts strings and numbers in both directions, keeping nulls last', () => {
    expect(sortRows(rows, columns, { key: 'name', dir: 'asc' }).map(r => r.name)).toEqual(['a', 'b', 'c'])
    expect(sortRows(rows, columns, { key: 'name', dir: 'desc' }).map(r => r.name)).toEqual(['c', 'b', 'a'])
    expect(sortRows(rows, columns, { key: 'rate', dir: 'asc' }).map(r => r.name)).toEqual(['c', 'b', 'a'])
    expect(sortRows(rows, columns, { key: 'rate', dir: 'desc' }).map(r => r.name)).toEqual(['b', 'c', 'a'])
  })
  it('leaves order alone when unsorted, unsortable or unknown, and never mutates the input', () => {
    const copy = [...rows]
    expect(sortRows(rows, columns, null)).toEqual(rows)
    expect(sortRows(rows, columns, { key: 'plain', dir: 'asc' })).toEqual(rows)
    expect(sortRows(rows, columns, { key: 'zzz', dir: 'asc' })).toEqual(rows)
    expect(rows).toEqual(copy)
  })
  it('is stable for equal keys', () => {
    const same: Row[] = [{ name: 'x', rate: 1 }, { name: 'y', rate: 1 }, { name: 'z', rate: 1 }]
    expect(sortRows(same, columns, { key: 'rate', dir: 'desc' }).map(r => r.name)).toEqual(['x', 'y', 'z'])
  })
})

describe('Table paging', () => {
  it('reports the visible range and the total', () => {
    expect(pageRange(1, 50, 55)).toEqual({ from: 1, to: 50, totalPages: 2, page: 1 })
    expect(pageRange(2, 50, 55)).toEqual({ from: 51, to: 55, totalPages: 2, page: 2 })
  })
  it('handles an empty result and out-of-range pages', () => {
    expect(pageRange(1, 25, 0)).toEqual({ from: 0, to: 0, totalPages: 1, page: 1 })
    expect(pageRange(9, 25, 30).page).toBe(2)
    expect(pageRange(-3, 25, 30).page).toBe(1)
    expect(pageRange(1, 25, 25).totalPages).toBe(1)
  })
})

describe('CIBar', () => {
  it('places the band and marker as percentages', () => {
    expect(ciGeometry(0.5, 0.25, 0.75)).toEqual({ left: 25, width: 50, marker: 50 })
  })
  it('clamps out-of-range and non-finite input and tolerates swapped bounds', () => {
    expect(ciGeometry(1.4, -0.2, 1.8)).toEqual({ left: 0, width: 100, marker: 100 })
    expect(ciGeometry(Number.NaN, 0.6, 0.2)).toEqual({ left: 20, width: 40, marker: 0 })
    expect(pct(0.256)).toBe('26%')
  })
})

describe('Meter and redaction helpers', () => {
  it('moves from ok to warn to danger as the budget fills', () => {
    expect(meterState(10, 100).level).toBe('ok')
    expect(meterState(75, 100).level).toBe('warn')
    expect(meterState(95, 100).level).toBe('danger')
    expect(meterState(5, 0)).toEqual({ fraction: 0, level: 'ok' })
    expect(meterState(500, 100).fraction).toBe(1)
  })
  it('splits redaction markers out of text without parsing markup', () => {
    expect(splitRedactions('key [REDACTED:api_key] and [REDACTED] done')).toEqual([
      { kind: 'text', value: 'key ' },
      { kind: 'redaction', value: '[REDACTED:api_key]', label: 'api_key' },
      { kind: 'text', value: ' and ' },
      { kind: 'redaction', value: '[REDACTED]', label: undefined },
      { kind: 'text', value: ' done' },
    ])
    const hostile = '<img src=x onerror=alert(1)><script>x</script>'
    expect(splitRedactions(hostile)).toEqual([{ kind: 'text', value: hostile }])
  })
})

describe('theme', () => {
  it('prefers the stored choice over the OS setting', () => {
    expect(resolveTheme(null, 'dark')).toBe('dark')
    expect(resolveTheme('light', 'dark')).toBe('light')
  })
})
