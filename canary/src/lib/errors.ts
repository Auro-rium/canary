export class ApiError extends Error {
  readonly status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/** FastAPI `detail` may be a string or a list of validation errors; never echo inputs. */
export function detailMessage(detail: unknown, fallback: string): string {
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail)) {
    const parts = detail
      .map(item => (item && typeof item === 'object' && 'msg' in item
        ? `${Array.isArray((item as { loc?: unknown[] }).loc) ? (item as { loc: unknown[] }).loc.slice(1).join('.') + ': ' : ''}${String((item as { msg: unknown }).msg)}`
        : ''))
      .filter(Boolean)
    if (parts.length) return parts.join('; ')
  }
  return fallback
}
