import { mkdirSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'
import { expectNoA11yViolations } from './a11y'
import { mockApi, type MockOptions } from './mockApi'

// Every page, in both themes: axe (WCAG 2.0/2.1/2.2 A and AA), and screenshots when SCREENSHOTS=1.
const SHOTS = process.env.SCREENSHOTS === '1'
const DIR = 'e2e/screenshots'

interface View { name: string; url: string; mock?: MockOptions; ready: (page: Page) => Promise<void>; readOnly?: boolean }

const heading = (name: string | RegExp) => async (page: Page) => { await expect(page.getByRole('heading', { level: 1, name })).toBeVisible() }

const views: View[] = [
  { name: 'login', url: '/campaigns', mock: { signedIn: false }, ready: heading('Sign in') },
  { name: 'targets', url: '/targets', ready: async p => { await expect(p.getByTestId('targets-table')).toBeVisible() }, readOnly: true },
  { name: 'target-new', url: '/targets/new', ready: heading('Add target') },
  { name: 'target-detail', url: '/targets/t-new', ready: async p => { await expect(p.getByTestId('verify-http_wellknown')).toBeVisible() } },
  { name: 'campaigns', url: '/campaigns', ready: async p => { await expect(p.getByTestId('campaigns-table')).toBeVisible() }, readOnly: true },
  { name: 'campaign-new-staging', url: '/campaigns/new?target=t-stage', ready: async p => { await expect(p.getByTestId('estimate')).toBeVisible() } },
  { name: 'campaign-new-production', url: '/campaigns/new?target=t-prod', ready: async p => { await expect(p.getByTestId('production-notice')).toBeVisible() } },
  { name: 'live', url: '/campaigns/camp1', ready: async p => { await expect(p.getByTestId('cell-prompt-injection-0')).toHaveAttribute('data-status', 'stopped_monitor') }, readOnly: true },
  { name: 'live-transcript', url: '/campaigns/camp1?conversation=c1&turn=1', mock: { role: 'admin' }, ready: async p => { await expect(p.getByTestId('turn-2')).toBeVisible() }, readOnly: true },
  { name: 'results', url: '/campaigns/camp1/results', mock: { completed: true }, ready: async p => { await expect(p.getByTestId('results-table')).toBeVisible() }, readOnly: true },
  { name: 'findings', url: '/findings', mock: { findingsTotal: 55 }, ready: async p => { await expect(p.getByTestId('finding')).toHaveCount(50) }, readOnly: true },
  { name: 'findings-board', url: '/findings?view=board', ready: async p => { await expect(p.getByTestId('lifecycle-board')).toBeVisible() }, readOnly: true },
  { name: 'reports', url: '/reports', mock: { completed: true }, ready: async p => { await expect(p.getByTestId('reports-table')).toBeVisible() }, readOnly: true },
  { name: 'admin', url: '/admin', mock: { role: 'admin' }, ready: heading('Admin') },
]

for (const colorScheme of ['light', 'dark'] as const) {
  test.describe(`${colorScheme} theme`, () => {
    test.use({ colorScheme })
    for (const view of views) {
      test(`axe: ${view.name}`, async ({ page }) => {
        await mockApi(page, view.mock)
        await page.goto(view.url)
        await view.ready(page)
        await expect(page.locator('html')).toHaveAttribute('data-theme', colorScheme)
        await expectNoA11yViolations(page, `${view.name} (${colorScheme})`)
        if (SHOTS) {
          mkdirSync(DIR, { recursive: true })
          await page.screenshot({ path: `${DIR}/${view.name}-${colorScheme}.png`, fullPage: true })
        }
      })
    }
  })
}

// Mobile: the read-only views must fit 375px with no horizontal page scroll.
test.describe('375px viewport', () => {
  test.use({ viewport: { width: 375, height: 812 } })
  const noSideScroll = async (page: Page, label: string) => {
    const { scroll, client } = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }))
    expect(scroll, `horizontal scroll on ${label}`).toBeLessThanOrEqual(client)
  }
  for (const colorScheme of ['light', 'dark'] as const) {
    test.describe(colorScheme, () => {
      test.use({ colorScheme })
      for (const view of views.filter(v => v.readOnly)) {
        test(`no horizontal scroll: ${view.name}`, async ({ page }) => {
          await mockApi(page, view.mock)
          await page.goto(view.url)
          await view.ready(page)
          await noSideScroll(page, view.name)
          if (view.name === 'live') {
            await page.getByTestId('cell-prompt-injection-0').click()
            await expect(page.getByTestId('turn-1')).toBeVisible()
            await noSideScroll(page, 'live with transcript drawer')
            await expectNoA11yViolations(page, `live drawer 375 (${colorScheme})`)
          }
          if (SHOTS) {
            mkdirSync(DIR, { recursive: true })
            await page.screenshot({ path: `${DIR}/${view.name}-375-${colorScheme}.png`, fullPage: true })
          }
        })
      }
    })
  }
})

test('theme toggle switches, persists, and follows the OS until chosen', async ({ page }) => {
  await mockApi(page)
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.goto('/targets')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.getByTestId('theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light') // stored choice beats the OS
})

test('theme still works when localStorage throws', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', { get() { throw new Error('blocked') } })
  })
  await mockApi(page)
  await page.goto('/targets')
  await page.getByTestId('theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', /light|dark/)
})

test('admin nav entry only for kill_switch:write; kill pill for everyone', async ({ page }) => {
  await mockApi(page, { role: 'viewer' })
  await page.goto('/targets')
  await expect(page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: 'Admin' })).toHaveCount(0)
  await expect(page.getByTestId('kill-pill')).toContainText('off')
  await page.goto('/admin')
  await expect(page.getByText('has no admin controls')).toBeVisible()
})

test('keyboard: Escape closes the transcript drawer and returns focus to the cell', async ({ page }) => {
  await mockApi(page)
  await page.goto('/campaigns/camp1')
  const cell = page.getByTestId('cell-prompt-injection-0')
  await expect(cell).toHaveAttribute('data-status', 'stopped_monitor')
  await cell.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('transcript-drawer')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('transcript-drawer')).toHaveCount(0)
  await expect(cell).toBeFocused()
})

test('375px: the transcript drawer is modal and Tab never leaves it', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 })
  await mockApi(page)
  await page.goto('/campaigns/camp1')
  const cell = page.getByTestId('cell-prompt-injection-0')
  await expect(cell).toHaveAttribute('data-status', 'stopped_monitor')
  await cell.focus()
  await page.keyboard.press('Enter')
  const drawer = page.getByTestId('transcript-drawer')
  await expect(drawer).toBeVisible()
  await expect(drawer).toHaveAttribute('aria-modal', 'true')
  const inside = () => page.evaluate(() => !!document.activeElement?.closest('[data-testid="transcript-drawer"]'))
  for (let i = 0; i < 25; i++) { await page.keyboard.press('Tab'); expect(await inside()).toBe(true) }
  for (let i = 0; i < 25; i++) { await page.keyboard.press('Shift+Tab'); expect(await inside()).toBe(true) }
  await page.keyboard.press('Escape')
  await expect(drawer).toHaveCount(0)
  await expect(cell).toBeFocused()
})

test('drawer: #root is inert below xl only, also after resizing across xl while open', async ({ page }) => {
  await mockApi(page)
  await page.setViewportSize({ width: 375, height: 800 })
  await page.goto('/campaigns/camp1')
  const cell = page.getByTestId('cell-prompt-injection-0')
  await expect(cell).toHaveAttribute('data-status', 'stopped_monitor')
  const rootInert = () => page.evaluate(() => (document.getElementById('root') as HTMLElement).inert)
  await cell.focus()
  await page.keyboard.press('Enter')
  const drawer = page.getByTestId('transcript-drawer')
  await expect(drawer).toBeVisible()
  expect(await rootInert()).toBe(true)
  await page.setViewportSize({ width: 1400, height: 800 })
  await expect(drawer).toHaveAttribute('aria-modal', 'false')
  expect(await rootInert()).toBe(false)
  await page.setViewportSize({ width: 375, height: 800 })
  await expect(drawer).toHaveAttribute('aria-modal', 'true')
  expect(await rootInert()).toBe(true)
  await page.keyboard.press('Escape')
  await expect(drawer).toHaveCount(0)
  expect(await rootInert()).toBe(false)
  await page.setViewportSize({ width: 1400, height: 800 })
  await cell.focus()
  await page.keyboard.press('Enter')
  await expect(drawer).toBeVisible()
  expect(await rootInert()).toBe(false)
})

test('drawer: live re-renders do not move focus or re-focus the panel', async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as { __panelFocus: number }
    w.__panelFocus = 0
    const original = HTMLElement.prototype.focus
    HTMLElement.prototype.focus = function (...args) {
      if (this.getAttribute('role') === 'dialog') w.__panelFocus += 1
      return original.apply(this, args)
    }
  })
  const mock = await mockApi(page)
  await page.setViewportSize({ width: 375, height: 800 })
  await page.goto('/campaigns/camp1')
  const cell = page.getByTestId('cell-prompt-injection-0')
  await expect(cell).toHaveAttribute('data-status', 'stopped_monitor')
  await cell.focus()
  await page.keyboard.press('Enter')
  const drawer = page.getByTestId('transcript-drawer')
  await expect(drawer).toBeVisible()
  await page.keyboard.press('Tab')
  const focusedId = () => page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null
    return { inDrawer: !!el?.closest('[data-testid="transcript-drawer"]'), isPanel: el?.getAttribute('role') === 'dialog', label: el?.getAttribute('aria-label') ?? el?.textContent?.slice(0, 20) ?? '' }
  })
  const before = await focusedId()
  expect(before.inDrawer).toBe(true)
  expect(before.isPanel).toBe(false)
  for (const id of ['c3', 'c4', 'c5']) {
    mock.pushConversation(id)
    await expect(page.getByTestId(`cell-prompt-injection-${id.slice(1)}`)).toBeAttached()
    await page.waitForTimeout(150)
  }
  expect(await focusedId()).toEqual(before)
  expect(await page.evaluate(() => (window as unknown as { __panelFocus: number }).__panelFocus)).toBe(1)
})

test('deep link from a finding opens the failing turn', async ({ page }) => {
  await mockApi(page)
  await page.goto('/findings')
  await page.getByRole('link', { name: 'Open transcript at turn 2' }).first().click()
  await expect(page.getByTestId('turn-1')).toHaveAttribute('data-failing', 'true')
})
