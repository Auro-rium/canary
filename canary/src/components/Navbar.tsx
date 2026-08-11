import { useEffect, useState } from 'react'
import { NavLink, Link } from 'react-router-dom'

const Logo = () => (
  <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 256 256" fill="none">
    <path d="M256 64v64h-63.5L160 95 128 64 96 95 63.5 128H64l64 64v64H64.5L32 223 0 192V64L64 0h128zm0 128v64h-63.5L160 223l-32-31v-64h64z" fill="white" />
  </svg>
)

const links = [
  { label: 'Campaigns', to: '/campaigns' },
  { label: 'Findings', to: '/findings' },
  { label: 'Targets', to: '/targets' },
]

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <nav className={`fixed inset-x-0 top-0 z-50 h-16 md:h-20 px-6 sm:px-10 md:px-16 lg:px-20 flex items-center justify-between transition-all duration-300 ${scrolled ? 'bg-black/85 backdrop-blur-md border-b border-white/10' : 'bg-transparent'}`}>
      <Link to="/" className="flex-shrink-0" aria-label="Agent Canary home"><Logo /></Link>
      <div className="hidden lg:flex items-center gap-8">
        {links.map(link => <NavLink key={link.to} to={link.to} className={({ isActive }) => `text-xs uppercase tracking-[0.2em] transition-colors ${isActive ? 'text-white' : 'text-white/55 hover:text-white'}`}>{link.label}</NavLink>)}
      </div>
      <div className="hidden lg:flex items-center gap-3">
        <Link to="/campaigns/new" className="px-5 py-2.5 bg-red-600 text-white text-xs uppercase tracking-[0.15em] font-medium hover:bg-red-500 transition-colors">Run audit</Link>
      </div>
      <button className="lg:hidden w-9 h-9 text-white" aria-label="Toggle navigation" aria-expanded={menuOpen} onClick={() => setMenuOpen(value => !value)}>
        <span className="block text-xl">{menuOpen ? '×' : '☰'}</span>
      </button>
      {menuOpen && <div className="absolute top-16 inset-x-0 bg-black border-y border-white/10 p-6 lg:hidden flex flex-col gap-5">
        {links.map(link => <NavLink key={link.to} to={link.to} onClick={() => setMenuOpen(false)} className="text-white/70 text-sm uppercase tracking-[0.2em]">{link.label}</NavLink>)}
        <Link to="/campaigns/new" onClick={() => setMenuOpen(false)} className="py-3 text-center bg-red-600 text-xs uppercase tracking-[0.15em]">Run audit</Link>
      </div>}
    </nav>
  )
}
