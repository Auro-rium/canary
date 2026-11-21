import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { MeProvider } from './components/Me'
import { useMe } from './lib/useMe'
import LoginPage from './pages/LoginPage'
import Navbar from './components/Navbar'
import HomePage from './pages/HomePage'
import CampaignsPage from './pages/CampaignsPage'
import CampaignNewPage from './pages/CampaignNewPage'
import CampaignDetailPage from './pages/CampaignDetailPage'
import FindingsPage from './pages/FindingsPage'
import TargetsPage from './pages/TargetsPage'
import TargetNewPage from './pages/TargetNewPage'
import TargetDetailPage from './pages/TargetDetailPage'
import './index.css'

function Gate() {
  const { loading, unauthenticated } = useMe()
  if (unauthenticated) return <><Navbar /><LoginPage /></>
  return <><Navbar />{loading ? <main className="min-h-screen bg-black pt-24 px-10 text-xs text-white/60" aria-busy="true"><h1 className="sr-only">Loading</h1>Loading…</main> : <Routes>
    <Route path="/" element={<HomePage />} />
    <Route path="/campaigns" element={<CampaignsPage />} />
    <Route path="/campaigns/new" element={<CampaignNewPage />} />
    <Route path="/campaigns/:campaignId" element={<CampaignDetailPage />} />
    <Route path="/findings" element={<FindingsPage />} />
    <Route path="/targets" element={<TargetsPage />} />
    <Route path="/targets/new" element={<TargetNewPage />} />
    <Route path="/targets/:targetId" element={<TargetDetailPage />} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>}</>
}

export default function App() {
  return <MeProvider><BrowserRouter><Gate /></BrowserRouter></MeProvider>
}
