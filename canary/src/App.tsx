import { useState } from 'react'
import './index.css'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import RunAuditPage from './pages/RunAuditPage'
import FindingsPage from './pages/FindingsPage'
import RedTeamPage from './pages/RedTeamPage'
import ConsoleLayout from './components/console/ConsoleLayout'

type Page = 'home' | 'audit' | 'findings' | 'redteam' | 'console'

export default function App() {
  const [page, setPage] = useState<Page>('home')

  const nav = (p: Page) => () => setPage(p)

  if (page === 'audit')    return <RunAuditPage onBack={nav('home')} />
  if (page === 'findings') return <FindingsPage onBack={nav('home')} onRunAudit={nav('audit')} onRedTeam={nav('redteam')} onConsole={nav('console')} />
  if (page === 'redteam')  return <RedTeamPage  onBack={nav('home')} onRunAudit={nav('audit')} onFindings={nav('findings')} onConsole={nav('console')} />
  if (page === 'console')  return <ConsoleLayout onBack={nav('home')} onRunAudit={nav('audit')} onFindings={nav('findings')} onRedTeam={nav('redteam')} />

  return (
    <main className="bg-black min-h-screen font-mono">
      <Navbar
        onRunAudit={nav('audit')}
        onFindings={nav('findings')}
        onRedTeam={nav('redteam')}
        showConsole={false}
      />
      <Hero onRunAudit={nav('audit')} />
    </main>
  )
}
