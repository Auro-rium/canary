import { useState } from 'react'
import './index.css'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import FindingsPage from './pages/FindingsPage'
import RedTeamPage from './pages/RedTeamPage'
import DefensesPage from './pages/DefensesPage'
import ConsoleLayout from './components/console/ConsoleLayout'

type Page = 'home' | 'findings' | 'redteam' | 'defenses' | 'console'

export default function App() {
  const [page, setPage] = useState<Page>('home')

  const nav = (p: Page) => () => setPage(p)

  if (page === 'findings') return <FindingsPage onBack={nav('home')} onRunAudit={nav('console')} onRedTeam={nav('redteam')} onDefenses={nav('defenses')} onConsole={nav('console')} />
  if (page === 'redteam')  return <RedTeamPage  onBack={nav('home')} onRunAudit={nav('console')} onFindings={nav('findings')} onDefenses={nav('defenses')} onConsole={nav('console')} />
  if (page === 'defenses') return <DefensesPage onBack={nav('home')} onRunAudit={nav('console')} onFindings={nav('findings')} onRedTeam={nav('redteam')} onConsole={nav('console')} />
  if (page === 'console')  return <ConsoleLayout onBack={nav('home')} onFindings={nav('findings')} onRedTeam={nav('redteam')} onDefenses={nav('defenses')} />

  return (
    <main className="bg-black min-h-screen font-mono">
      <Navbar
        onRunAudit={nav('console')}
        onFindings={nav('findings')}
        onRedTeam={nav('redteam')}
        onDefenses={nav('defenses')}
        onConsole={nav('console')}
      />
      <Hero onRunAudit={nav('console')} />
    </main>
  )
}
