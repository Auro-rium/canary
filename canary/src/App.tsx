import { useEffect, useState } from 'react'
import './index.css'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import RunAuditPage from './pages/RunAuditPage'
import FindingsPage from './pages/FindingsPage'
import RedTeamPage from './pages/RedTeamPage'
import ConsoleLayout from './components/console/ConsoleLayout'
import ProjectsPage from './pages/ProjectsPage'
import AuthGate from './components/AuthGate'
import { getSession, loginWithGitHub, logout, type AuthSession } from './lib/auth'

type Page = 'home' | 'audit' | 'findings' | 'redteam' | 'console' | 'projects'

export default function App() {
  const [page, setPage] = useState<Page>('home')
  const [session, setSession] = useState<AuthSession | null>(null)
  const [authLoading, setAuthLoading] = useState(true)
  const [authError, setAuthError] = useState('')

  useEffect(() => {
    void getSession().then(setSession).catch((cause) => {
      setAuthError(cause instanceof Error ? cause.message : 'Unable to check GitHub session')
    }).finally(() => setAuthLoading(false))
  }, [])

  const nav = (p: Page) => () => setPage(p)

  if (authLoading || authError || !session?.authenticated) {
    return <AuthGate session={session} loading={authLoading} error={authError} onLogin={loginWithGitHub} />
  }

  const signOut = () => {
    void logout().then(() => {
      setSession({ authenticated: false, user: null })
      setPage('home')
    }).catch((cause) => setAuthError(cause instanceof Error ? cause.message : 'Unable to sign out of Canary'))
  }

  if (page === 'audit')    return <RunAuditPage onBack={nav('home')} />
  if (page === 'findings') return <FindingsPage onBack={nav('home')} onRunAudit={nav('audit')} onRedTeam={nav('redteam')} onConsole={nav('console')} />
  if (page === 'redteam')  return <RedTeamPage  onBack={nav('home')} onRunAudit={nav('audit')} onFindings={nav('findings')} onConsole={nav('console')} />
  if (page === 'console')  return <ConsoleLayout onBack={nav('home')} onRunAudit={nav('audit')} onFindings={nav('findings')} onRedTeam={nav('redteam')} />
  if (page === 'projects') return <ProjectsPage onBack={nav('home')} />

  return (
    <main className="bg-black min-h-screen font-mono">
      <Navbar
        onRunAudit={nav('audit')}
        onFindings={nav('findings')}
        onRedTeam={nav('redteam')}
        onConsole={nav('console')}
        onProjects={nav('projects')}
        user={session.user}
        onLogout={signOut}
      />
      <Hero onRunAudit={nav('audit')} />
    </main>
  )
}
