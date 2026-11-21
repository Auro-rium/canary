import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'

/** Fails (and lists every rule, node and impact) on any axe-core violation. */
export async function expectNoA11yViolations(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze()
  const report = results.violations.map(v => `${v.impact} ${v.id}: ${v.help} (${v.nodes.length} node(s)) e.g. ${v.nodes[0]?.target.join(' ')}`)
  expect(report, `axe violations on ${label}`).toEqual([])
}
