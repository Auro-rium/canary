import { useState } from 'react'
import './index.css'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import RunAuditPage from './pages/RunAuditPage'

type Page = 'home' | 'audit'

export default function App() {
  const [page, setPage] = useState<Page>('home')

  if (page === 'audit') {
    return <RunAuditPage onBack={() => setPage('home')} />
  }

  return (
    <main className="bg-black min-h-screen font-mono">
      <Navbar onRunAudit={() => setPage('audit')} />
      <Hero />
    </main>
  )
}
