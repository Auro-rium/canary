import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { MeProvider } from './components/Me'
import { KillSwitchProvider } from './components/KillSwitch'
import { Shell } from './components/Shell'
import { ThemeToggle } from './components/ThemeToggle'
import { SkeletonList, ToastProvider } from './components/ui'
import { useMe } from './lib/useMe'
import AdminPage from './pages/AdminPage'
import CampaignDetailPage from './pages/CampaignDetailPage'
import CampaignNewPage from './pages/CampaignNewPage'
import CampaignsPage from './pages/CampaignsPage'
import FindingsPage from './pages/FindingsPage'
import ReportsPage from './pages/ReportsPage'
import ResultsPage from './pages/ResultsPage'
import LoginPage from './pages/LoginPage'
import TargetDetailPage from './pages/TargetDetailPage'
import TargetNewPage from './pages/TargetNewPage'
import TargetsPage from './pages/TargetsPage'

function Gate() {
  const { loading, unauthenticated, error } = useMe()
  if (unauthenticated) {
    return (
      <div className="min-h-screen">
        <div className="flex justify-end p-3"><ThemeToggle /></div>
        <main id="main"><LoginPage /></main>
      </div>
    )
  }
  if (loading) return <main className="mx-auto max-w-3xl p-gutter pt-16"><h1 className="sr-only">Loading</h1><SkeletonList rows={5} label="Loading console" /></main>
  if (error) return <main className="mx-auto max-w-3xl p-gutter pt-16"><h1 className="mb-2 text-xl font-semibold">Cannot reach the API</h1><p role="alert" className="text-danger">{error}</p></main>
  return (
    <KillSwitchProvider>
      <Shell>
        <Routes>
          <Route path="/" element={<Navigate to="/campaigns" replace />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/targets/new" element={<TargetNewPage />} />
          <Route path="/targets/:targetId" element={<TargetDetailPage />} />
          <Route path="/campaigns" element={<CampaignsPage />} />
          <Route path="/campaigns/new" element={<CampaignNewPage />} />
          <Route path="/campaigns/:campaignId" element={<CampaignDetailPage />} />
          <Route path="/campaigns/:campaignId/results" element={<ResultsPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="*" element={<Navigate to="/campaigns" replace />} />
        </Routes>
      </Shell>
    </KillSwitchProvider>
  )
}

export default function App() {
  return <ToastProvider><MeProvider><BrowserRouter><Gate /></BrowserRouter></MeProvider></ToastProvider>
}
