// Theme: follows the OS until the user picks one; the choice lives in localStorage (always in
// try/catch: storage can throw in private windows or be blocked).
export type Theme = 'light' | 'dark'
export const THEME_KEY = 'canary-theme'

export function readStoredTheme(): Theme | null {
  try {
    const value = window.localStorage.getItem(THEME_KEY)
    return value === 'light' || value === 'dark' ? value : null
  } catch { return null }
}

export function storeTheme(theme: Theme) {
  try { window.localStorage.setItem(THEME_KEY, theme) } catch { /* storage unavailable: the choice lasts this session */ }
}

export function systemTheme(): Theme {
  try { return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light' } catch { return 'light' }
}

export const resolveTheme = (stored: Theme | null, system: Theme): Theme => stored ?? system

export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme
}

/** Call once before first render. Tracks OS changes until the user chooses explicitly. */
export function initTheme() {
  applyTheme(resolveTheme(readStoredTheme(), systemTheme()))
  try {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (!readStoredTheme()) applyTheme(systemTheme())
    })
  } catch { /* no matchMedia */ }
}
