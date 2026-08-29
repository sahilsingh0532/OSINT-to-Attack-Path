import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import Dashboard from './pages/Dashboard';
import Reconnaissance from './pages/Reconnaissance';
import OsintSources from './pages/OsintSources';
import AttackSurface from './pages/AttackSurface';
import AttackPaths from './pages/AttackPaths';
import RiskAnalysis from './pages/RiskAnalysis';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Defense from './pages/Defense';
import Timeline from './pages/Timeline';
import Reports from './pages/Reports';
import Research from './pages/Research';
import Settings from './pages/Settings';
import EmailIntelligence from './pages/EmailIntelligence';
import UsernameIntel from './pages/UsernameIntel';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<MainLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/reconnaissance" element={<Reconnaissance />} />
          <Route path="/sources" element={<OsintSources />} />
          <Route path="/attack-surface" element={<AttackSurface />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/risk-analysis" element={<RiskAnalysis />} />
          <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
          <Route path="/defense" element={<Defense />} />
          <Route path="/timeline" element={<Timeline />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/research" element={<Research />} />
          <Route path="/settings" element={<Settings />} />
          {/* New intelligence pages */}
          <Route path="/email-intelligence" element={<EmailIntelligence />} />
          <Route path="/username-intel" element={<UsernameIntel />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
