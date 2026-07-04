import { useState } from 'react'
import './index.css'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import RunAuditPage from './pages/RunAuditPage'
import FindingsPage from './pages/FindingsPage'
import RedTeamPage from './pages/RedTeamPage'

type Page = 'home' | 'audit' | 'findings' | 'redteam'

export default function App() {
  const [page, setPage] = useState<Page>('home')

  const nav = (p: Page) => () => setPage(p)

  if (page === 'audit')    return <RunAuditPage onBack={nav('home')} />
  if (page === 'findings') return <FindingsPage onBack={nav('home')} onRunAudit={nav('audit')} onRedTeam={nav('redteam')} />
  if (page === 'redteam')  return <RedTeamPage  onBack={nav('home')} onRunAudit={nav('audit')} onFindings={nav('findings')} />

  return (
    <main className="bg-black min-h-screen font-mono">
      <Navbar
        onRunAudit={nav('audit')}
        onFindings={nav('findings')}
        onRedTeam={nav('redteam')}
      />
      <Hero onRunAudit={nav('audit')} />
    </main>
  )
}
