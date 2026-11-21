/** @type {import('tailwindcss').Config} */
// Every color, size, radius and shadow resolves to a CSS variable defined in src/index.css, so the
// light and dark themes only differ in that one file. Colors are RGB channel triplets so Tailwind's
// opacity modifiers (bg-danger/10) keep working.
const color = name => `rgb(var(--c-${name}) / <alpha-value>)`
const tones = ['danger', 'warn', 'ok', 'info', 'violet', 'fuchsia']

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      bg: color('bg'),
      surface: color('surface'),
      raised: color('raised'),
      line: color('line'),
      'line-strong': color('line-strong'),
      fg: color('fg'),
      muted: color('muted'),
      accent: color('accent'),
      'accent-hover': color('accent-hover'),
      'accent-fg': color('accent-fg'),
      ring: color('ring'),
      ...Object.fromEntries(tones.flatMap(tone => [[tone, color(tone)], [`${tone}-soft`, color(`${tone}-soft`)]])),
    },
    fontFamily: {
      sans: ['"Inter Variable"', 'Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
      mono: ['"JetBrains Mono Variable"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
    },
    fontSize: {
      xs: ['var(--text-xs)', { lineHeight: 'var(--lh-xs)' }],
      sm: ['var(--text-sm)', { lineHeight: 'var(--lh-sm)' }],
      base: ['var(--text-base)', { lineHeight: 'var(--lh-base)' }],
      lg: ['var(--text-lg)', { lineHeight: 'var(--lh-lg)' }],
      xl: ['var(--text-xl)', { lineHeight: 'var(--lh-xl)' }],
      '2xl': ['var(--text-2xl)', { lineHeight: 'var(--lh-2xl)' }],
    },
    borderRadius: {
      none: '0',
      sm: 'var(--radius-sm)',
      DEFAULT: 'var(--radius-md)',
      md: 'var(--radius-md)',
      lg: 'var(--radius-lg)',
      full: '9999px',
    },
    boxShadow: {
      none: 'none',
      e1: 'var(--shadow-1)',
      e2: 'var(--shadow-2)',
      e3: 'var(--shadow-3)',
    },
    extend: {
      spacing: { gutter: 'var(--space-gutter)', section: 'var(--space-section)', bar: 'var(--size-topbar)', nav: 'var(--size-sidenav)', drawer: 'var(--size-drawer)' },
    },
  },
  plugins: [],
}
