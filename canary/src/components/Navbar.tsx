import { useState, useEffect } from 'react'

const Logo = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 256 256" fill="none">
    <path
      d="M 256 64 L 256 128 L 192.5 128 L 160 95 L 128 64 L 96 95 L 63.5 128 L 64 128 L 128 192 L 128 256 L 64.5 256 L 32 223 L 0 192 L 0 64 L 64 0 L 192 0 Z M 256 192 L 256 256 L 192.5 256 L 160 223 L 128 192 L 128 128 L 192 128 Z"
      fill="white"
    />
  </svg>
)

const NAV_LINKS = [
  { label: 'Red Team',  key: 'redteam'  },
  { label: 'Defenses',  key: 'defenses' },
  { label: 'Findings',  key: 'findings' },
]

interface NavbarProps {
  onRunAudit?: () => void
  onLogoClick?: () => void
  onRedTeam?: () => void
  onDefenses?: () => void
  onFindings?: () => void
}

export default function Navbar({ onRunAudit, onLogoClick, onRedTeam, onDefenses, onFindings }: NavbarProps) {
  const handlers: Record<string, (() => void) | undefined> = {
    redteam: onRedTeam, defenses: onDefenses, findings: onFindings,
  }
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    if (menuOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => { document.body.style.overflow = '' }
  }, [menuOpen])

  return (
    <>
      <nav
        className={`fixed top-0 left-0 right-0 z-50 h-16 md:h-20 px-6 sm:px-10 md:px-16 lg:px-20 flex items-center justify-between transition-all duration-300 ${
          scrolled ? 'bg-black/70 backdrop-blur-md' : 'bg-transparent'
        }`}
      >
        {/* Logo */}
        <a href={onLogoClick ? undefined : '/'} onClick={onLogoClick} className="flex-shrink-0 cursor-pointer">
          <Logo />
        </a>

        {/* Desktop nav links */}
        <div className="hidden lg:flex items-center gap-8">
          {NAV_LINKS.map(({ label, key }) => (
            <button
              key={key}
              onClick={handlers[key]}
              className="text-white/70 text-xs uppercase tracking-[0.2em] font-light hover:text-white transition-colors duration-200"
            >
              {label}
            </button>
          ))}
        </div>

        {/* Desktop CTAs */}
        <div className="hidden lg:flex items-center gap-3">
          <button className="px-5 py-2.5 border border-white/30 text-white text-xs uppercase tracking-[0.15em] font-light hover:border-white/60 transition-all duration-200">
            Request Access
          </button>
          <button
            onClick={onRunAudit}
            className="px-5 py-2.5 bg-red-600 text-white text-xs uppercase tracking-[0.15em] font-medium hover:bg-red-500 transition-all duration-200"
          >
            Run Audit
          </button>
        </div>

        {/* Mobile hamburger */}
        <button
          className="lg:hidden flex flex-col justify-center items-center w-8 h-8 gap-1.5 relative z-50"
          onClick={() => setMenuOpen((v) => !v)}
          aria-label="Toggle menu"
        >
          <span
            className="w-6 h-[1.5px] bg-white block transition-all duration-300 ease-out origin-center"
            style={menuOpen ? { transform: 'translateY(4.5px) rotate(45deg)' } : {}}
          />
          <span
            className="w-6 h-[1.5px] bg-white block transition-all duration-300 ease-out"
            style={menuOpen ? { opacity: 0, transform: 'scaleX(0)' } : {}}
          />
          <span
            className="w-6 h-[1.5px] bg-white block transition-all duration-300 ease-out origin-center"
            style={menuOpen ? { transform: 'translateY(-4.5px) rotate(-45deg)' } : {}}
          />
        </button>
      </nav>

      {/* Mobile menu overlay */}
      <div
        className={`fixed inset-0 z-40 bg-black lg:hidden flex flex-col transition-opacity duration-500 ${
          menuOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
        }`}
      >
        <div className="flex flex-col justify-center flex-1 px-6 sm:px-10 pt-20">
          {NAV_LINKS.map(({ label, key }, i) => (
            <button
              key={key}
              onClick={() => { setMenuOpen(false); handlers[key]?.() }}
              className="flex items-center justify-between w-full py-6 border-b border-white/10 group"
              style={{
                transitionProperty: 'opacity, transform',
                transitionDuration: '0.5s',
                transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)',
                transitionDelay: menuOpen ? `${i * 60 + 150}ms` : '0ms',
                opacity: menuOpen ? 1 : 0,
                transform: menuOpen ? 'translateY(0)' : 'translateY(20px)',
              }}
            >
              <span className="text-2xl sm:text-3xl font-light tracking-tight text-white group-hover:text-white/70 transition-colors duration-200">
                {label}
              </span>
              <span className="text-red-600/60 text-xs font-light">
                0{i + 1}
              </span>
            </button>
          ))}

          {/* Mobile CTAs */}
          <div
            className="flex flex-col gap-3 mt-10"
            style={{
              transitionProperty: 'opacity, transform',
              transitionDuration: '0.5s',
              transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)',
              transitionDelay: menuOpen ? '400ms' : '0ms',
              opacity: menuOpen ? 1 : 0,
              transform: menuOpen ? 'translateY(0)' : 'translateY(20px)',
            }}
          >
            <button className="w-full py-4 border border-white/30 text-white text-xs uppercase tracking-[0.15em] font-light hover:border-white/60 transition-all duration-200">
              Request Access
            </button>
            <button
              onClick={() => { setMenuOpen(false); onRunAudit?.() }}
              className="w-full py-4 bg-red-600 text-white text-xs uppercase tracking-[0.15em] font-medium hover:bg-red-500 transition-all duration-200"
            >
              Run Audit
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
