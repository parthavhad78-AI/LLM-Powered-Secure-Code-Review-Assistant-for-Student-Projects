import { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppShell, type NavSection } from './layouts/AppShell';
import { AssistantPage } from './pages/AssistantPage';
import { FindingsPage } from './pages/FindingsPage';
import { LearningCenterPage } from './pages/LearningCenterPage';
import { LoginPage } from './pages/LoginPage';
import { NewScanPage } from './pages/NewScanPage';
import { OverviewPage } from './pages/OverviewPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { RegisterPage } from './pages/RegisterPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

interface NavContext {
  projectId?: string;
  scanId?: string;
  topicSlug?: string;
}

function SecureLensRouter() {
  const { user, loading } = useAuth();
  const [authView, setAuthView] = useState<'login' | 'register'>('login');
  const [section, setSection] = useState<NavSection>('overview');
  const [navCtx, setNavCtx] = useState<NavContext>({});

  function handleNavigate(nextSection: NavSection, context?: NavContext) {
    setSection(nextSection);
    setNavCtx(context || {});
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#080d1a] flex items-center justify-center">
        <div className="text-sm text-slate-400">Loading SecureLens workspace...</div>
      </div>
    );
  }

  if (!user) {
    return authView === 'login' ? (
      <LoginPage onSwitchToRegister={() => setAuthView('register')} />
    ) : (
      <RegisterPage onSwitchToLogin={() => setAuthView('login')} />
    );
  }

  return (
    <AppShell activeSection={section} onNavigate={(s) => handleNavigate(s)}>
      {section === 'overview' && <OverviewPage onNavigate={handleNavigate} />}
      {section === 'projects' && <ProjectsPage onNavigate={handleNavigate} />}
      {section === 'new-scan' && (
        <NewScanPage initialProjectId={navCtx.projectId} onNavigate={handleNavigate} />
      )}
      {section === 'findings' && (
        <FindingsPage
          initialProjectId={navCtx.projectId}
          initialScanId={navCtx.scanId}
          onNavigate={handleNavigate}
        />
      )}
      {section === 'assistant' && <AssistantPage initialProjectId={navCtx.projectId} />}
      {section === 'learning' && <LearningCenterPage initialTopicSlug={navCtx.topicSlug} />}
      {section === 'reports' && <ReportsPage />}
      {section === 'settings' && <SettingsPage />}
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <SecureLensRouter />
    </AuthProvider>
  );
}
