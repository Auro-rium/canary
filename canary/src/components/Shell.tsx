import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { logout } from '../lib/api'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { KillSwitchPill } from './KillSwitch'
import { ThemeToggle } from './ThemeToggle'
import { cx } from './ui'

const Logo = () => (
  <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 256 256" fill="none">
    <path d="M256 64v64h-63.5L160 95 128 64 96 95 63.5 128H64l64 64v64H64.5L32 223 0 192V64L64 0h128zm0 128v64h-63.5L160 223l-32-31v-64h64z" fill="currentColor" />
  </svg>
)

const NAV = [
  { label: 'Targets', to: '/targets', icon: '◎' },
  { label: 'Campaigns', to: '/campaigns', icon: '▶' },
  { label: 'Findings', to: '/findings', icon: '⚑' },
  { label: 'Reports', to: '/reports', icon: '▤' },
  { label: 'Admin', to: '/admin', icon: '⚙', permission: PERMISSION.killSwitchWrite },
]

function signOut() {
  logout().catch(() => undefined).finally(() => window.location.assign('/'))
}

/** Authenticated console frame: top bar (user, role, kill-switch status, theme, sign-out) and left nav. */
export function Shell({ children }: { children: ReactNode }) {
  const { me } = useMe()
  const [menu, setMenu] = useState(false)
  const location = useLocation()
  useEffect(() => setMenu(false), [location.pathname])
  const who = me ? (me.display_name || me.email || me.user_id) : ''
  const items = NAV.filter(item => !item.permission || can(me, item.permission))

  return (
    <div className="min-h-screen">
      <a href="#main" className="skip-link">Skip to content</a>
      <header className="fixed inset-x-0 top-0 z-30 flex h-bar items-center gap-2 border-b border-line bg-surface px-3 sm:px-gutter">
        <button type="button" className="rounded-md border border-line-strong px-2.5 py-1.5 text-sm font-medium hover:bg-raised lg:hidden" aria-expanded={menu} aria-controls="sidenav" onClick={() => setMenu(value => !value)}>
          <span aria-hidden="true">{menu ? '✕' : '☰'}</span><span className="sr-only">Menu</span>
        </button>
        <span className="flex items-center gap-2 font-semibold"><Logo /><span className="hidden sm:inline">Canary</span></span>
        <span className="flex-1" />
        <KillSwitchPill />
        {me && <span data-testid="role-badge" className="hidden max-w-[16rem] truncate text-xs text-muted sm:inline" title={`${who} (${me.org_id})`}>{who} · {me.role}</span>}
        <ThemeToggle />
        {me && <button type="button" data-testid="sign-out" onClick={signOut} className="rounded-md border border-line-strong px-2.5 py-1.5 text-sm font-medium hover:bg-raised">Sign out</button>}
      </header>
      <nav id="sidenav" aria-label="Primary" className={cx('fixed bottom-0 left-0 top-bar z-20 w-full border-r border-line bg-surface p-3 sm:w-nav lg:block lg:w-nav', menu ? 'block shadow-e3' : 'hidden')}>
        {me && <p className="mb-3 border-b border-line pb-3 text-xs text-muted sm:hidden">{who} · {me.role} · {me.org_id}</p>}
        <ul className="space-y-1">
          {items.map(item => (
            <li key={item.to}>
              <NavLink to={item.to} className={({ isActive }) => cx('flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium', isActive ? 'bg-raised text-fg ring-1 ring-line-strong' : 'text-muted hover:bg-raised hover:text-fg')}>
                <span aria-hidden="true" className="w-4 text-center">{item.icon}</span>{item.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <main id="main" tabIndex={-1} className="min-w-0 pt-bar outline-none lg:pl-nav">
        {children}
      </main>
    </div>
  )
}
