import type { ReactNode } from 'react'
import { cx } from './tones'

export type SortDir = 'asc' | 'desc'
export interface SortState { key: string; dir: SortDir }

export interface Column<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  /** Present = the column is sortable by this value. */
  sortValue?: (row: T) => string | number | null | undefined
  className?: string
}

export interface Paging { page: number; pageSize: number; total: number; onPageChange: (page: number) => void }

/** asc -> desc -> unsorted. */
export function nextSort(current: SortState | null, key: string): SortState | null {
  if (!current || current.key !== key) return { key, dir: 'asc' }
  return current.dir === 'asc' ? { key, dir: 'desc' } : null
}

/** Stable sort by a column's sortValue; null/undefined sort last in either direction. */
export function sortRows<T>(rows: readonly T[], columns: readonly Column<T>[], sort: SortState | null): T[] {
  const column = sort && columns.find(c => c.key === sort.key)
  if (!sort || !column?.sortValue) return [...rows]
  const value = column.sortValue
  const sign = sort.dir === 'asc' ? 1 : -1
  return rows
    .map((row, index) => ({ row, index, v: value(row) }))
    .sort((a, b) => {
      const aNull = a.v === null || a.v === undefined
      const bNull = b.v === null || b.v === undefined
      if (aNull || bNull) return aNull === bNull ? a.index - b.index : aNull ? 1 : -1
      const cmp = typeof a.v === 'number' && typeof b.v === 'number' ? a.v - b.v : String(a.v).localeCompare(String(b.v))
      return cmp === 0 ? a.index - b.index : cmp * sign
    })
    .map(item => item.row)
}

export function pageRange(page: number, pageSize: number, total: number) {
  const totalPages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)))
  const current = Math.min(Math.max(1, page), totalPages)
  const from = total === 0 ? 0 : (current - 1) * pageSize + 1
  const to = Math.min(current * pageSize, total)
  return { from, to, totalPages, page: current }
}

export function PageControls({ paging }: { paging: Paging }) {
  const { from, to, totalPages, page } = pageRange(paging.page, paging.pageSize, paging.total)
  const button = 'rounded-md border border-line-strong px-3 py-1.5 text-sm font-medium hover:bg-raised disabled:cursor-not-allowed disabled:opacity-50'
  return (
    <nav aria-label="Pagination" className="mt-3 flex items-center justify-between gap-2 text-sm">
      <button type="button" className={button} disabled={page <= 1} onClick={() => paging.onPageChange(page - 1)}>Previous</button>
      <span className="text-muted" aria-live="polite">{from}–{to} of {paging.total}</span>
      <button type="button" className={button} disabled={page >= totalPages} onClick={() => paging.onPageChange(page + 1)}>Next</button>
    </nav>
  )
}

/** Typed table: optional sorting (of the rows given) and server paging with the total count. Scrolls inside itself. */
export function Table<T>({ columns, rows, rowKey, caption, sort, onSortChange, paging, className, testId }: {
  columns: readonly Column<T>[]
  rows: readonly T[]
  rowKey: (row: T) => string
  caption: string
  /** Controlled sort; omit both sort props for an uncontrolled table. */
  sort?: SortState | null
  onSortChange?: (sort: SortState | null) => void
  paging?: Paging
  className?: string
  testId?: string
}) {
  const sorted = sortRows(rows, columns, sort ?? null)
  return (
    <div className={className}>
      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        <table className="w-full text-left text-sm" data-testid={testId}>
          <caption className="sr-only">{caption}</caption>
          <thead className="bg-raised text-xs text-muted">
            <tr>
              {columns.map(column => {
                const active = sort?.key === column.key ? sort.dir : null
                return (
                  <th key={column.key} scope="col" aria-sort={active ? (active === 'asc' ? 'ascending' : 'descending') : column.sortValue ? 'none' : undefined}
                    className={cx('whitespace-nowrap px-3 py-2 font-semibold', column.className)}>
                    {column.sortValue && onSortChange
                      ? <button type="button" onClick={() => onSortChange(nextSort(sort ?? null, column.key))} className="inline-flex items-center gap-1 font-semibold hover:text-fg">
                          {column.header}<span aria-hidden="true">{active === 'asc' ? '▲' : active === 'desc' ? '▼' : '↕'}</span>
                        </button>
                      : column.header}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {sorted.map(row => (
              <tr key={rowKey(row)} className="border-t border-line align-top">
                {columns.map(column => <td key={column.key} className={cx('px-3 py-2.5', column.className)}>{column.cell(row)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {paging && <PageControls paging={paging} />}
    </div>
  )
}
