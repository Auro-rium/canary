import { defineConfig } from '@playwright/test'

// All backend calls are intercepted in the tests (page.route); the dev server only serves the SPA.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  workers: 2,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:5199', trace: 'retain-on-failure' },
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 5199 --strictPort',
    url: 'http://127.0.0.1:5199',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
})
