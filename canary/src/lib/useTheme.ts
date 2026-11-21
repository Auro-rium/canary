import { useCallback, useState } from 'react'
import { applyTheme, storeTheme, type Theme } from './theme'

export function useTheme(): { theme: Theme; toggle: () => void } {
  const read = (): Theme => (document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light')
  const [theme, setTheme] = useState<Theme>(read)
  const toggle = useCallback(() => {
    const next: Theme = read() === 'dark' ? 'light' : 'dark'
    applyTheme(next)
    storeTheme(next)
    setTheme(next)
  }, [])
  return { theme, toggle }
}
