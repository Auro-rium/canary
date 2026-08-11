import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import Navbar from './components/Navbar'
import HomePage from './pages/HomePage'
import CampaignsPage from './pages/CampaignsPage'
import CampaignNewPage from './pages/CampaignNewPage'
import CampaignDetailPage from './pages/CampaignDetailPage'
import FindingsPage from './pages/FindingsPage'
import TargetsPage from './pages/TargetsPage'
import TargetDetailPage from './pages/TargetDetailPage'
import './index.css'

export default function App() {
  return <BrowserRouter><Navbar /><Routes>
    <Route path="/" element={<HomePage />} />
    <Route path="/campaigns" element={<CampaignsPage />} />
    <Route path="/campaigns/new" element={<CampaignNewPage />} />
    <Route path="/campaigns/:runId" element={<CampaignDetailPage />} />
    <Route path="/findings" element={<FindingsPage />} />
    <Route path="/targets" element={<TargetsPage />} />
    <Route path="/targets/:targetId" element={<TargetDetailPage />} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes></BrowserRouter>
}
