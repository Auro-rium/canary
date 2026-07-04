import { get, set, del, keys } from 'idb-keyval'
import type { CompletePayload } from './types'

const PREFIX = 'canary-run:'

export async function saveRun(payload: CompletePayload): Promise<void> {
  await set(`${PREFIX}${payload.campaign_id}`, payload)
}

export async function loadRunHistory(): Promise<CompletePayload[]> {
  const allKeys = await keys()
  const runKeys = allKeys.filter((k): k is string => typeof k === 'string' && k.startsWith(PREFIX))
  const items = await Promise.all(runKeys.map((k) => get<CompletePayload>(k)))
  return items.filter((x): x is CompletePayload => Boolean(x))
}

export async function deleteRun(campaignId: string): Promise<void> {
  await del(`${PREFIX}${campaignId}`)
}
