import { expect, test } from '@playwright/test'
import { XSS_MESSAGE, XSS_RESPONSE } from './fixtures'
import { mockApi } from './mockApi'

// Reviewer-requested regression: text that comes from a target is attacker-controlled. It must be
// shown as inert text, never parsed as markup.
for (const role of ['operator', 'admin'] as const) {
  test(`target output with markup renders as inert text (${role})`, async ({ page }) => {
    await mockApi(page, { role })
    const dialogs: string[] = []
    page.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss() })

    await page.goto('/campaigns/camp1?conversation=c1')
    const transcript = page.getByTestId('transcript')
    await expect(transcript).toContainText(XSS_RESPONSE)
    await expect(transcript).toContainText(XSS_MESSAGE)
    await expect(page.getByTestId('turn-2')).toBeVisible()

    const check = async () => {
      expect(await transcript.locator('img, script, svg, [onerror], [onload]').count()).toBe(0)
      expect(await page.locator('#root script').count()).toBe(0)
      expect(await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss)).toBeUndefined()
      expect(dialogs).toEqual([])
    }
    await check()

    if (role === 'admin') {
      await page.getByTestId('toggle-raw').click()
      await expect(page.getByTestId('raw-banner')).toBeVisible()
      await expect(transcript).toContainText(XSS_RESPONSE)
      await check()
    }
    await page.waitForTimeout(300) // give a would-be onerror handler time to fire
    expect(dialogs).toEqual([])
  })
}
