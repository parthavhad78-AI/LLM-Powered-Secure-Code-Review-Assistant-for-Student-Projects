import React, { useState } from 'react';
import {
  BookOpen,
  Bot,
  FileBarChart2,
  FolderGit2,
  LayoutDashboard,
  LogOut,
  Menu,
  Play,
  Settings,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export type NavSection =
  | 'overview'
  | 'projects'
  | 'new-scan'
  | 'findings'
  | 'assistant'
  | 'learning'
  | 'reports'
  | 'settings';

const NAV_ITEMS: Array<{ id: NavSection; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'projects', label: 'Projects', icon: FolderGit2 },
  { id: 'new-scan', label: 'New Security Scan', icon: Play },
  { id: 'findings', label: 'Findings', icon: ShieldAlert },
  { id: 'assistant', label: 'AI Security Assistant', icon: Bot },
  { id: 'learning', label: 'Learning Center', icon: BookOpen },
  { id: 'reports', label: 'Reports', icon: FileBarChart2 },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export function AppShell({
  activeSection,
  onNavigate,
  children,
}: {
  activeSection: NavSection;
  onNavigate: (section: NavSection) => void;
  children: React.ReactNode;
}) {
  const { user, logout } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const activeLabel = NAV_ITEMS.find((n) => n.id === activeSection)?.label || 'Overview';

  function handleNavClick(id: NavSection) {
    onNavigate(id);
    setMobileMenuOpen(false);
  }

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex w-64 shrink-0 flex-col border-r border-slate-800/90 bg-[#0b1120]">
        <div className="flex h-16 items-center gap-2.5 border-b border-slate-800/90 px-5">
          <ShieldCheck className="h-5 w-5 text-cyan-400 shrink-0" />
          <span className="font-display text-lg font-semibold tracking-tight text-slate-100 whitespace-nowrap">
            SecureLens
          </span>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-4 overflow-y-auto" aria-label="Main Navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNavClick(item.id)}
                className={`w-full flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-cyan-500/12 text-cyan-300 border border-cyan-500/25'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="border-t border-slate-800/90 p-4 space-y-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-slate-200">{user?.fullName}</p>
            <p className="truncate text-xs text-slate-500">{user?.email}</p>
          </div>
          <button
            type="button"
            onClick={() => logout()}
            className="w-full flex items-center justify-center gap-2 rounded-lg border border-slate-800 bg-[#0e1526] px-3 py-2 text-xs font-medium text-slate-300 hover:border-slate-700 hover:text-slate-100 transition-colors whitespace-nowrap"
          >
            <LogOut className="h-3.5 w-3.5 shrink-0" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <aside className="relative z-10 w-64 max-w-[80vw] bg-[#0b1120] border-r border-slate-800 flex flex-col h-full">
            <div className="flex h-16 items-center justify-between border-b border-slate-800 px-5">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-cyan-400" />
                <span className="font-display text-lg font-semibold text-slate-100">SecureLens</span>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-100"
                aria-label="Close navigation"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <nav className="flex-1 space-y-1 px-3 py-4 overflow-y-auto">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activeSection === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => handleNavClick(item.id)}
                    className={`w-full flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium whitespace-nowrap ${
                      active
                        ? 'bg-cyan-500/12 text-cyan-300 border border-cyan-500/25'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                    }`}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </nav>
            <div className="border-t border-slate-800 p-4">
              <button
                type="button"
                onClick={() => logout()}
                className="w-full flex items-center justify-center gap-2 rounded-lg border border-slate-800 bg-[#0e1526] px-3 py-2 text-xs font-medium text-slate-300"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* Main Content Viewport */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-16 shrink-0 border-b border-slate-800/90 bg-[#080d1a]/95 backdrop-blur px-4 sm:px-8 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden rounded-lg border border-slate-800 p-2 text-slate-300 hover:text-slate-100"
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="flex items-center gap-2 text-sm min-w-0">
              <span className="text-slate-500 hidden sm:inline">Workspace</span>
              <span className="text-slate-600 hidden sm:inline">/</span>
              <span className="font-display font-semibold text-slate-100 truncate">{activeLabel}</span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {activeSection !== 'new-scan' && (
              <button
                type="button"
                onClick={() => onNavigate('new-scan')}
                className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 transition-colors whitespace-nowrap shrink-0"
              >
                <Play className="h-3.5 w-3.5 shrink-0" />
                <span>New Security Scan</span>
              </button>
            )}
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-8 max-w-[1440px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
