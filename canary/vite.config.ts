import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'

// `vite preview` serves the production build with the same security headers as vercel.json (single source),
// so the CSP can be exercised by Playwright (`npm run test:csp`).
const vercel = JSON.parse(readFileSync(new URL('./vercel.json', import.meta.url), 'utf8')) as { headers: { headers: { key: string; value: string }[] }[] }
const securityHeaders = Object.fromEntries(vercel.headers[0].headers.map(h => [h.key, h.value]))

export default defineConfig({
  plugins: [react()],
  // Never inline fonts as data: URIs, so the CSP can keep font-src 'self'.
  build: { assetsInlineLimit: (file: string) => (file.endsWith('.woff2') || file.endsWith('.woff') ? false : undefined) },
  preview: { headers: securityHeaders },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8001',
        changeOrigin: true,
        ws: false,
        timeout: 300000,
      },
    },
  },
})
