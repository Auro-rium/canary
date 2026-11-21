import { defineConfig } from '@playwright/test'

// The whole e2e suite against the production build served by `vite preview` with the vercel.json security
// headers (including the CSP). e2e/csp.spec.ts asserts no CSP violation is reported.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  workers: 2,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:5198', trace: 'retain-on-failure' },
  webServer: {
    command: 'npm run build && npx vite preview --host 127.0.0.1 --port 5198 --strictPort',
    url: 'http://127.0.0.1:5198',
    reuseExistingServer: false,
    timeout: 180_000,
  },
})
