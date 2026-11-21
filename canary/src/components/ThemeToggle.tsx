import { useTheme } from '../lib/useTheme'

export function ThemeToggle() {
  const { theme, toggle } = useTheme()
  const next = theme === 'dark' ? 'light' : 'dark'
  return (
    <button type="button" data-testid="theme-toggle" onClick={toggle} aria-label={`Switch to ${next} theme`}
      className="inline-flex items-center gap-1.5 rounded-md border border-line-strong px-2.5 py-1.5 text-sm font-medium hover:bg-raised">
      <span aria-hidden="true">{theme === 'dark' ? '☀' : '☾'}</span>
      <span className="hidden md:inline">{next === 'dark' ? 'Dark' : 'Light'}</span>
    </button>
  )
}
