import React, { useState } from 'react';
import { Lock, Mail, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export function LoginPage({ onSwitchToRegister }: { onSwitchToRegister: () => void }) {
  const { login, sessionNotice, clearSessionNotice } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    clearSessionNotice();
    setSubmitting(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to sign in.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#080d1a] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h1 className="font-display text-xl font-semibold text-slate-100 tracking-tight">
              SecureLens
            </h1>
            <p className="text-xs text-slate-400">Student Secure Code Review Platform</p>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 sm:p-7 space-y-5">
          <div>
            <h2 className="font-display text-lg font-semibold text-slate-100">Student Sign In</h2>
            <p className="mt-1 text-sm text-slate-400">
              Sign in to access your isolated code workspaces, scan history, and AI remediation assistant.
            </p>
          </div>

          {sessionNotice && !error && (
            <div className="rounded-lg border border-amber-800/70 bg-amber-950/35 px-3.5 py-2.5 text-sm text-amber-200">
              {sessionNotice}
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-3.5 py-2.5 text-sm text-rose-200">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="login-email" className="block text-xs font-medium text-slate-300">
                Student Email
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  id="login-email"
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="student@university.edu"
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] py-2 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="login-password" className="block text-xs font-medium text-slate-300">
                Password
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  id="login-password"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] py-2 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 transition-colors whitespace-nowrap"
            >
              {submitting ? 'Signing In...' : 'Sign In'}
            </button>
          </form>

          <div className="border-t border-slate-800/80 pt-4 text-center text-sm text-slate-400">
            New to SecureLens?{' '}
            <button
              type="button"
              onClick={onSwitchToRegister}
              className="font-medium text-cyan-400 hover:text-cyan-300"
            >
              Create a student account
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
