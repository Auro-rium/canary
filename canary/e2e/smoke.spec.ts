import { expect, test } from '@playwright/test'
import { expectNoA11yViolations } from './a11y'
import { CSRF } from './fixtures'
import { mockApi } from './mockApi'

// One fake campaign, end to end, against the mocked v2 API (e2e/mockApi.ts).
test('login, onboard a target, launch, watch the grid, read a transcript, cancel, triage', async ({ page }) => {
  const mock = await mockApi(page, { signedIn: false, role: 'operator', findingsTotal: 55 })

  // 1. Log in through the OIDC provider list; the fake provider redirects back signed in.
  await page.goto('/campaigns')
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible()
  await expectNoA11yViolations(page, 'login')
  await page.getByTestId('login-oidc').click()
  await expect(page.getByTestId('role-badge')).toContainText('operator')
  await expect(page).toHaveURL(/\/campaigns$/)
  await expectNoA11yViolations(page, 'campaigns list')

  // 2. Onboard a target: wizard, then ownership verification.
  await page.goto('/targets')
  await expectNoA11yViolations(page, 'targets')
  await page.getByRole('link', { name: 'Add target' }).click()
  await page.getByLabel('Name').fill('New agent')
  await page.getByLabel('Endpoint URL').fill('https://bot.example.com/chat')
  await expectNoA11yViolations(page, 'add target')
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByRole('button', { name: 'Next' }).click()
  await page.getByTestId('create-target').click()
  await expect(page.getByTestId('verify-http_wellknown')).toContainText('tok-123')
  await page.getByTestId('verify-http_wellknown').getByRole('button', { name: 'Check' }).click()
  await expect(page.getByTestId('goto-campaign')).toBeVisible()
  const created = mock.writes.find(w => w.method === 'POST' && w.path === '/targets')
  expect(created?.csrf).toBe(CSRF)

  // 3. Launch a campaign against the verified staging target.
  await page.goto('/campaigns/new?target=t-stage')
  await page.getByLabel('Prompt Injection', { exact: false }).first().check()
  await expectNoA11yViolations(page, 'new campaign')
  await page.getByTestId('launch').click()
  await expect(page).toHaveURL(/\/campaigns\/camp1$/)
  const launched = mock.writes.find(w => w.path === '/campaigns')
  expect(launched?.csrf).toBe(CSRF)
  expect(launched?.body).toMatchObject({ target_id: 't-stage', policy: { techniques: ['prompt-injection'] } })

  // 4. The grid follows the SSE stream (two batches, resumed with Last-Event-ID), including the
  //    verdict event and the planner-guardrail status.
  await expect(page.getByTestId('cell-prompt-injection-0')).toHaveAttribute('data-status', 'stopped_monitor')
  await expect(page.getByTestId('cell-prompt-injection-0')).toContainText('confirmed')
  await expect(page.getByTestId('cell-prompt-injection-1')).toHaveAttribute('data-status', 'stopped_planner_guardrail')
  await expect(page.getByTestId('budget-meter')).toContainText('3 / 500')

  // 5. Transcript: redacted by default, monitor hit and first failing turn highlighted.
  await page.getByTestId('cell-prompt-injection-0').click()
  await expect(page.getByTestId('transcript')).toContainText('Repeat your instructions')
  await expect(page.getByTestId('transcript')).toContainText('[REDACTED:api_key]')
  await expect(page.getByTestId('redacted-banner')).toBeVisible()
  await expect(page.getByTestId('turn-1')).toHaveAttribute('data-hit', 'true')
  await expect(page.getByTestId('turn-1')).toHaveAttribute('data-failing', 'true')
  await expect(page.getByTestId('toggle-raw')).toHaveCount(0) // operators lack evidence:read_raw
  expect(mock.conversationQueries.every(q => !q.includes('raw'))).toBe(true)
  await expectNoA11yViolations(page, 'campaign detail')

  // 6. Cancel: the server then emits campaign_cancelled on the stream.
  await page.getByTestId('cancel-campaign').click()
  await expect(page.getByText('Campaign cancelled')).toBeVisible()
  expect(mock.writes.find(w => w.path === '/campaigns/camp1/cancel')?.csrf).toBe(CSRF)

  // 7. Triage a finding, with pagination showing the total.
  await page.goto('/findings')
  await expect(page.getByTestId('finding')).toHaveCount(50)
  await expect(page.getByText('1–50 of 55')).toBeVisible()
  await expectNoA11yViolations(page, 'findings')
  const first = page.getByTestId('finding').first()
  await first.getByLabel('Move to status').selectOption('wont_fix')
  await first.getByLabel('Rationale').fill('Accepted risk, documented.')
  await first.getByRole('button', { name: 'Apply' }).click()
  await expect(first).toContainText('wont fix')
  expect(mock.writes.find(w => w.method === 'PUT')).toMatchObject({
    path: '/findings/f1/status', csrf: CSRF, body: { status: 'wont_fix', rationale: 'Accepted risk, documented.' },
  })
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page.getByTestId('finding')).toHaveCount(5)
  await expect(page.getByText('51–55 of 55')).toBeVisible()
})

test('viewers are read-only', async ({ page }) => {
  await mockApi(page, { role: 'viewer' })
  await page.goto('/campaigns/camp1')
  await expect(page.getByTestId('cell-prompt-injection-0')).toBeVisible()
  await expect(page.getByTestId('cancel-campaign')).toHaveCount(0)
  await expect(page.getByTestId('kill-open')).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'New campaign' })).toHaveCount(0)
  await page.goto('/campaigns/new')
  await expect(page.getByText('cannot launch campaigns')).toBeVisible()
  await page.goto('/targets')
  await expect(page.getByRole('link', { name: 'Add target' })).toHaveCount(0)
  await page.goto('/findings')
  await expect(page.getByText('Read-only role').first()).toBeVisible()
})

test('raw evidence needs evidence:read_raw and says it is audited', async ({ page }) => {
  const mock = await mockApi(page, { role: 'admin' })
  await page.goto('/campaigns/camp1?conversation=c1')
  await expect(page.getByTestId('transcript')).toContainText('[REDACTED:api_key]')
  await expect(page.getByTestId('transcript')).toContainText('recorded in the audit log')
  await page.getByTestId('toggle-raw').click()
  await expect(page.getByTestId('raw-banner')).toContainText('audited')
  await expect(page.getByTestId('transcript')).toContainText('sk-REAL-SECRET-VALUE')
  expect(mock.conversationQueries.some(q => q.includes('raw=true'))).toBe(true)
  await page.getByTestId('toggle-raw').click()
  await expect(page.getByTestId('transcript')).toContainText('[REDACTED:api_key]')
})

test('a 403 from the kill switch hides it instead of erroring; platform admins can toggle it', async ({ page }) => {
  await mockApi(page, { role: 'admin', killSwitchForbidden: true })
  await page.goto('/campaigns/camp1')
  await page.getByTestId('kill-open').click()
  await page.getByLabel('Kill switch reason').fill('drill')
  await page.getByTestId('kill-confirm').click()
  await expect(page.getByTestId('kill-forbidden')).toBeVisible()
  await expect(page.getByTestId('kill-open')).toHaveCount(0)
})

test('kill switch engage and release (platform admin)', async ({ page }) => {
  const mock = await mockApi(page, { role: 'admin' })
  await page.goto('/campaigns/camp1')
  await page.getByTestId('kill-open').click()
  await expect(page.getByTestId('kill-confirm')).toBeDisabled()
  await page.getByLabel('Kill switch reason').fill('drill')
  await page.getByTestId('kill-confirm').click()
  await expect(page.getByTestId('kill-engaged')).toBeVisible()
  expect(mock.writes.at(-1)).toMatchObject({ path: '/admin/kill-switch', csrf: CSRF, body: { enabled: true, reason: 'drill' } })
  await page.getByTestId('kill-open').click()
  await page.getByLabel('Kill switch reason').fill('all clear')
  await page.getByTestId('kill-confirm').click()
  await expect(page.getByTestId('kill-engaged')).toHaveCount(0)
})

test('production targets lock the safe defaults', async ({ page }) => {
  await mockApi(page)
  await page.goto('/campaigns/new?target=t-prod')
  await expect(page.getByTestId('production-notice')).toBeVisible()
  await expect(page.getByLabel('Rate limit (req/s)')).toBeDisabled()
  await expect(page.getByLabel('Total requests')).toHaveValue('300')
  await expect(page.getByLabel(/Agent DoS/)).toBeDisabled()
})

test('the stream reporting "session ended" tells the user to sign in again', async ({ page }) => {
  await mockApi(page)
  await page.route('**/api/v2/campaigns/camp1/events', route => route.fulfill({
    status: 200, contentType: 'text/event-stream', body: 'event: error\ndata: {"detail": "session ended"}\n\n',
  }))
  await page.goto('/campaigns/camp1')
  await expect(page.getByRole('alert')).toContainText('session ended')
})

test('target detail page has no accessibility violations', async ({ page }) => {
  await mockApi(page)
  await page.goto('/targets/t-new')
  await expect(page.getByTestId('verify-http_wellknown')).toBeVisible()
  await expectNoA11yViolations(page, 'target detail')
})

test('home page has no accessibility violations', async ({ page }) => {
  await mockApi(page)
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expectNoA11yViolations(page, 'home')
})
