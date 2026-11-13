import { isSseEventType, type SseEvent } from './contracts'
import { ApiError } from './errors'

/** One parsed SSE frame (`id:` / `event:` / `data:` lines ended by a blank line). */
export interface SseFrame {
  id?: string
  event?: string
  data: string
}

/** Incremental SSE parser: feed text chunks, get complete frames back. */
export class SseParser {
  private buffer = ''
  private id: string | undefined
  private event: string | undefined
  private data: string[] = []

  push(chunk: string): SseFrame[] {
    this.buffer += chunk
    const frames: SseFrame[] = []
    let newline = this.buffer.search(/\r\n|\n|\r/)
    while (newline >= 0) {
      const match = /\r\n|\n|\r/.exec(this.buffer.slice(newline))!
      const line = this.buffer.slice(0, newline)
      this.buffer = this.buffer.slice(newline + match[0].length)
      const frame = this.line(line)
      if (frame) frames.push(frame)
      newline = this.buffer.search(/\r\n|\n|\r/)
    }
    return frames
  }

  private line(line: string): SseFrame | null {
    if (line === '') {
      if (this.data.length === 0) {
        this.id = undefined
        this.event = undefined
        return null
      }
      const frame: SseFrame = { id: this.id, event: this.event, data: this.data.join('\n') }
      this.id = undefined
      this.event = undefined
      this.data = []
      return frame
    }
    if (line.startsWith(':')) return null // comment / keep-alive
    const colon = line.indexOf(':')
    const field = colon < 0 ? line : line.slice(0, colon)
    let value = colon < 0 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'data') this.data.push(value)
    else if (field === 'id') this.id = value
    else if (field === 'event') this.event = value
    return null
  }
}

/** Turn a frame into a typed event, or null when it is not a known v2 event. */
export function frameToEvent(frame: SseFrame): SseEvent | null {
  let parsed: unknown
  try { parsed = JSON.parse(frame.data) } catch { return null }
  if (!parsed || typeof parsed !== 'object') return null
  const candidate = parsed as { type?: unknown; seq?: unknown }
  if (typeof candidate.type !== 'string' || !isSseEventType(candidate.type)) return null
  if (typeof candidate.seq !== 'number') {
    const fromId = Number(frame.id)
    if (!Number.isFinite(fromId)) return null
    ;(candidate as { seq: number }).seq = fromId
  }
  return parsed as SseEvent
}

const TERMINAL = new Set(['campaign_complete', 'campaign_failed', 'campaign_cancelled'])

export interface StreamOptions {
  url: string
  onEvent: (event: SseEvent) => void
  /** Highest seq already applied (e.g. from the campaign snapshot); resume after it. */
  lastSeq?: number
  signal?: AbortSignal
  onStatus?: (status: 'connected' | 'reconnecting') => void
  maxRetries?: number
  retryDelayMs?: (attempt: number) => number
  fetchImpl?: typeof fetch
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>
}

export function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
  })
}

/**
 * Follow a campaign event stream until a terminal event, reconnecting with
 * `Last-Event-ID` after a drop. Events with seq <= the last applied seq are
 * dropped, so a replay after reconnect never double-applies. Resolves when the
 * campaign is terminal or the signal aborts; throws ApiError on 4xx or when
 * retries are exhausted.
 */
export async function followEvents(options: StreamOptions): Promise<number> {
  const {
    url, onEvent, signal, onStatus, maxRetries = 8,
    retryDelayMs = attempt => Math.min(500 * 2 ** attempt, 10_000),
    fetchImpl = fetch, sleep = defaultSleep,
  } = options
  let lastSeq = options.lastSeq ?? 0
  let attempt = 0
  while (!signal?.aborted) {
    try {
      const headers: Record<string, string> = { Accept: 'text/event-stream' }
      if (lastSeq > 0) headers['Last-Event-ID'] = String(lastSeq)
      const response = await fetchImpl(url, { headers, credentials: 'include', signal })
      if (!response.ok) {
        // Client errors are final (auth, not found); server errors are retried.
        if (response.status >= 400 && response.status < 500 && response.status !== 429) {
          throw new ApiError(`Event stream refused (${response.status})`, response.status)
        }
        throw new Error(`stream ${response.status}`)
      }
      if (!response.body) throw new Error('no stream body')
      onStatus?.('connected')
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      const parser = new SseParser()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
          const event = frameToEvent(frame)
          if (!event || event.seq <= lastSeq) continue
          lastSeq = event.seq
          attempt = 0
          onEvent(event)
          if (TERMINAL.has(event.type)) return lastSeq
        }
      }
      // Stream closed without a terminal event: fall through and reconnect.
    } catch (error) {
      if (signal?.aborted) return lastSeq
      if (error instanceof ApiError) throw error
    }
    if (signal?.aborted) break
    if (attempt >= maxRetries) throw new ApiError('Lost the live event stream; reload to resume.')
    onStatus?.('reconnecting')
    await sleep(retryDelayMs(attempt), signal)
    attempt += 1
  }
  return lastSeq
}
