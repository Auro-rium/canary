import { expect, test } from '@playwright/test'
import { mockApi } from './mockApi'

// Runs only against `vite preview` (npm run test:csp), which sends the vercel.json security headers.
test.skip(!process.env.CSP_PREVIEW, 'needs the production build with security headers (npm run test:csp)')

test('the built app runs under the CSP with no violations', async ({ page }) => {
  const violations: string[] = []
  page.on('console', msg => { if (/content security policy/i.test(msg.text())) violations.push(msg.text()) })
  page.on('pageerror', err => violations.push(err.message))
  await page.addInitScript(() => document.addEventListener('securitypolicyviolation', e => { console.error(`Content Security Policy violation: ${e.violatedDirective} ${e.blockedURI}`) }))
  await mockApi(page, { completed: true })
  const response = await page.goto('/campaigns')
  const headers = response!.headers()
  expect(headers['content-security-policy']).toContain("script-src 'self'")
  expect(headers['content-security-policy']).toContain("frame-ancestors 'none'")
  expect(headers['x-content-type-options']).toBe('nosniff')
  expect(headers['referrer-policy']).toBe('no-referrer')
  await expect(page.getByTestId('campaigns-table')).toBeVisible()
  for (const url of ['/targets', '/findings', '/reports', '/campaigns/camp1?conversation=c1&turn=1']) {
    await page.goto(url)
    await expect(page.getByRole('main')).toBeVisible()
  }
  await expect(page.getByTestId('transcript-drawer')).toBeVisible()
  expect(violations).toEqual([])
})
