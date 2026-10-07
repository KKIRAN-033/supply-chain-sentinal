import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { api } from './api/client';

import Dashboard from './pages/Dashboard';
import Projects from './pages/Projects';
import ProjectDetails from './pages/ProjectDetails';
import SBOMUpload from './pages/SBOMUpload';
import ScanDetails from './pages/ScanDetails';
import Findings from './pages/Findings';
import Policies from './pages/Policies';

import Repositories from './pages/Repositories';
import SBOMIntelligence from './pages/SBOMIntelligence';
import DependenciesPage from './pages/DependenciesPage';
import GraphPage from './pages/GraphPage';
import DeterministicRiskPage from './pages/DeterministicRiskPage';
import AttackPathsPage from './pages/AttackPathsPage';
import CICDSecurity from './pages/CICDSecurity';
import RemediationCenter from './pages/RemediationCenter';
import WhatIfSimulator from './pages/WhatIfSimulator';
import MonitoringPage from './pages/MonitoringPage';
import AlertsPage from './pages/AlertsPage';
import ReportsPage from './pages/ReportsPage';
import AuditLogsPage from './pages/AuditLogsPage';
import SettingsPage from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';

import SecurityAIModal, { SecurityAIContext } from './components/SecurityAIModal';

interface NavSection {
  title: string;
  items: { to: string; label: string; icon: string }[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: 'CORE PLATFORM',
    items: [
      { to: '/dashboard', label: 'Overview', icon: '📊' },
      { to: '/projects', label: 'Projects', icon: '📁' },
      { to: '/repositories', label: 'Repositories', icon: '📦' },
    ],
  },
  {
    title: 'SUPPLY CHAIN INTELLIGENCE',
    items: [
      { to: '/sbom', label: 'SBOM Intelligence', icon: '📑' },
      { to: '/dependencies', label: 'Dependencies', icon: '📦' },
      { to: '/graph', label: 'Dependency Graph', icon: '🕸️' },
      { to: '/findings', label: 'Vulnerability Findings', icon: '🔍' },
      { to: '/risk', label: 'Deterministic Risk', icon: '⚖️' },
      { to: '/attack-paths', label: 'Attack Paths', icon: '⚡' },
    ],
  },
  {
    title: 'GOVERNANCE & REMEDIATION',
    items: [
      { to: '/policies', label: 'Policy Engine', icon: '📜' },
      { to: '/cicd', label: 'CI/CD Security', icon: '⚙️' },
      { to: '/remediation', label: 'Remediation Center', icon: '🛠️' },
      { to: '/simulator', label: 'What-If Simulator', icon: '🔮' },
    ],
  },
  {
    title: 'OPERATIONS & AUDIT',
    items: [
      { to: '/monitoring', label: 'Continuous Monitoring', icon: '📡' },
      { to: '/alerts', label: 'Alerts', icon: '🚨' },
      { to: '/reports', label: 'Executive Reports', icon: '📑' },
      { to: '/audit-logs', label: 'Audit Evidence Log', icon: '📜' },
      { to: '/settings', label: 'Settings', icon: '⚙️' },
    ],
  },
];

function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [currentUser, setCurrentUser] = useState<any>(() => {
    try {
      const saved = localStorage.getItem('sentinel_user');
      const token = localStorage.getItem('sentinel_auth_token');
      return saved && token ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [projects, setProjects] = useState<any[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [aiContext, setAiContext] = useState<SecurityAIContext>({ projectId: '' });

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {}
    localStorage.removeItem('sentinel_auth_token');
    localStorage.removeItem('sentinel_user');
    setCurrentUser(null);
  };

  if (!currentUser) {
    return <LoginPage onLoginSuccess={(u) => setCurrentUser(u)} />;
  }

  useEffect(() => {
    api.listProjects()
      .then(prjs => {
        setProjects(prjs);
        if (prjs.length > 0) {
          const saved = localStorage.getItem('sentinel_active_project');
          const current = prjs.find(p => p.id === saved) ? saved! : prjs[0].id;
          setActiveProjectId(current);
          localStorage.setItem('sentinel_active_project', current);
        }
      })
      .catch(console.error);
  }, [location.pathname]);

  // Listen to project switch events from child pages
  useEffect(() => {
    const handleProj = (e: any) => {
      if (e.detail && e.detail !== activeProjectId) {
        setActiveProjectId(e.detail);
      }
    };
    window.addEventListener('sentinel:project-change', handleProj);
    return () => window.removeEventListener('sentinel:project-change', handleProj);
  }, [activeProjectId]);

  // Global event listener for opening AI Security Analyst from any component
  useEffect(() => {
    const handleOpenAI = (e: any) => {
      const detail = e.detail || {};
      setAiContext({
        projectId: detail.projectId || activeProjectId,
        scanId: detail.scanId,
        findingId: detail.findingId,
        finding: detail.finding,
        componentPurl: detail.componentPurl,
        initialQuestion: detail.question,
        initialMode: detail.mode,
      });
      setAiModalOpen(true);
    };

    window.addEventListener('open-ai-analyst', handleOpenAI);
    return () => window.removeEventListener('open-ai-analyst', handleOpenAI);
  }, [activeProjectId]);

  const handleProjectSelect = (id: string) => {
    setActiveProjectId(id);
    localStorage.setItem('sentinel_active_project', id);
    // Reload or notify active page
    window.dispatchEvent(new Event('storage'));
    window.dispatchEvent(new CustomEvent('sentinel:project-change', { detail: id }));
  };

  const handleGlobalSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/findings?search=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-sentinel-bg text-gray-100 font-sans">
      {/* Mobile Backdrop */}
      {sidebarOpen && (
        <div
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs lg:hidden"
        />
      )}

      {/* Enterprise Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-sentinel-surface border-r border-sentinel-border flex flex-col shrink-0 transition-transform duration-200 lg:static lg:translate-x-0 ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        {/* Brand Header */}
        <div className="p-4 border-b border-sentinel-border flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-gradient-to-br from-blue-600 to-cyan-500 rounded-lg flex items-center justify-center text-lg shadow-md shadow-blue-500/20">
              🛡️
            </div>
            <div>
              <h1 className="text-sm font-bold text-white tracking-wider">SENTINEL</h1>
              <p className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Supply-Chain Security</p>
            </div>
          </div>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden text-gray-400 hover:text-white p-1"
          >
            ✕
          </button>
        </div>

        {/* Navigation Sections */}
        <nav className="flex-1 px-3 py-4 space-y-6 overflow-y-auto">
          {NAV_SECTIONS.map((section, sIdx) => (
            <div key={sIdx} className="space-y-1">
              <h2 className="px-3 text-[10px] font-bold text-gray-500 uppercase tracking-wider">
                {section.title}
              </h2>
              {section.items.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  onClick={() => setSidebarOpen(false)}
                  className={({ isActive }) => `sidebar-link py-2 px-3 text-xs ${isActive ? 'active font-semibold' : ''}`}
                >
                  <span className="text-sm">{item.icon}</span>
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Sidebar Footer */}
        <div className="p-3.5 border-t border-sentinel-border bg-sentinel-surface/80 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-gray-400">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
            <span className="text-[11px] font-medium">Deterministic Core</span>
          </div>
          <span className="text-[10px] font-mono text-gray-500">v1.2 SaaS</span>
        </div>
      </aside>

      {/* Main Workspace Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header Bar */}
        <header className="h-16 bg-sentinel-surface/90 border-b border-sentinel-border px-4 lg:px-6 flex items-center justify-between gap-4 shrink-0 z-10 backdrop-blur-md">
          {/* Left: Mobile hamburger & Organization */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-2 rounded-lg bg-sentinel-card text-gray-400 hover:text-white"
            >
              ☰
            </button>
            <div className="hidden sm:block">
              <span className="text-[10px] uppercase tracking-wider text-gray-500 font-bold block">Organization</span>
              <span className="text-xs font-bold text-gray-200">Default Organization (Active)</span>
            </div>
          </div>

          {/* Center: Project Switcher & Search Bar */}
          <div className="flex items-center gap-3 flex-1 max-w-xl">
            {/* Project Selector */}
            <div className="w-48 hidden md:block">
              <select
                value={activeProjectId}
                onChange={e => handleProjectSelect(e.target.value)}
                className="input-field py-1 px-2.5 text-xs font-semibold bg-sentinel-card border-sentinel-border"
              >
                {projects.map(p => (
                  <option key={p.id} value={p.id}>
                    📁 {p.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Global Search Bar */}
            <form onSubmit={handleGlobalSearch} className="flex-1 relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-xs">🔍</span>
              <input
                type="text"
                placeholder="Search packages, CVEs, or findings..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="input-field pl-8 py-1.5 text-xs bg-sentinel-card border-sentinel-border"
              />
            </form>
          </div>

          {/* Right: CTA & User Identity */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                setAiContext({ projectId: activeProjectId });
                setAiModalOpen(true);
              }}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600/30 to-cyan-600/30 hover:from-blue-600/50 hover:to-cyan-600/50 border border-cyan-500/50 text-cyan-300 hover:text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm shadow-cyan-500/10 transition-all cursor-pointer"
              title="Consult AI Security Analyst"
            >
              <span>🤖</span>
              <span className="hidden sm:inline">AI Analyst</span>
            </button>

            <button
              onClick={() => navigate(activeProjectId ? `/upload?project=${activeProjectId}` : '/upload')}
              className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5 font-semibold"
            >
              <span>⬆️</span> Run Scan
            </button>

            <button
              onClick={() => navigate('/alerts')}
              className="relative p-2 text-gray-400 hover:text-white bg-sentinel-card rounded-lg border border-sentinel-border text-xs"
              title="View Security Alerts"
            >
              🔔
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500"></span>
            </button>

            {/* User Profile & Logout */}
            <div className="flex items-center gap-2 pl-2 border-l border-sentinel-border">
              <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center text-[11px] font-bold text-white uppercase">
                {currentUser?.name ? currentUser.name.slice(0, 2) : 'SE'}
              </div>
              <div className="hidden lg:block text-left">
                <span className="text-xs font-bold text-white block leading-tight">{currentUser?.name || 'Security Lead'}</span>
                <span className="text-[10px] text-gray-500 block leading-tight">{currentUser?.role === 'admin' ? 'Security Admin' : 'Security Analyst'}</span>
              </div>
              <button
                onClick={handleLogout}
                className="ml-1 px-2 py-1 rounded-lg text-gray-400 hover:text-red-400 hover:bg-red-950/40 border border-transparent hover:border-red-800/50 text-xs font-medium transition-colors flex items-center gap-1"
                title="Sign Out"
              >
                <span>🚪</span>
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </header>

        {/* Page Content Body */}
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/projects/:projectId" element={<ProjectDetails />} />
            <Route path="/repositories" element={<Repositories />} />
            <Route path="/upload" element={<SBOMUpload />} />
            <Route path="/scan/:scanId" element={<ScanDetails />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:scanId" element={<Findings />} />
            <Route path="/sbom" element={<SBOMIntelligence />} />
            <Route path="/dependencies" element={<DependenciesPage />} />
            <Route path="/graph" element={<GraphPage />} />
            <Route path="/risk" element={<DeterministicRiskPage />} />
            <Route path="/attack-paths" element={<AttackPathsPage />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/cicd" element={<CICDSecurity />} />
            <Route path="/remediation" element={<RemediationCenter />} />
            <Route path="/simulator" element={<WhatIfSimulator />} />
            <Route path="/monitoring" element={<MonitoringPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/audit-logs" element={<AuditLogsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>

        {/* Unified Security AI Analyst Modal */}
        <SecurityAIModal
          isOpen={aiModalOpen}
          onClose={() => setAiModalOpen(false)}
          context={aiContext}
        />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}
