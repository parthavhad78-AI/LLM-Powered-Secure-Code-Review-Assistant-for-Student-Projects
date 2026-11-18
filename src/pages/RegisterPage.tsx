import React, { useState } from 'react';
import { Lock, Mail, ShieldCheck, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export function RegisterPage({ onSwitchToLogin }: { onSwitchToLogin: () => void }) {
  const { register } = useAuth();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await register({ fullName, email, password, confirmPassword });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to register account.');
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
            <h2 className="font-display text-lg font-semibold text-slate-100">Create Student Account</h2>
            <p className="mt-1 text-sm text-slate-400">
              Register for a private workspace to scan and remediate your software projects.
            </p>
          </div>

          {error && (
            <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-3.5 py-2.5 text-sm text-rose-200">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="reg-name" className="block text-xs font-medium text-slate-300">
                Full Name
              </label>
              <div className="relative">
                <User className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  id="reg-name"
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Aarav Sharma"
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] py-2 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="reg-email" className="block text-xs font-medium text-slate-300">
                Email Address
              </label>
              <div className="relative">
                <Mail className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  id="reg-email"
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
              <label htmlFor="reg-pass" className="block text-xs font-medium text-slate-300">
                Password
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  id="reg-pass"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 8 chars, upper, lower & digit"
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] py-2 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="reg-confirm" className="block text-xs font-medium text-slate-300">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  id="reg-confirm"
                  type="password"
                  required
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter password"
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] py-2 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 transition-colors whitespace-nowrap"
            >
              {submitting ? 'Creating Account...' : 'Create Student Account'}
            </button>
          </form>

          <div className="border-t border-slate-800/80 pt-4 text-center text-sm text-slate-400">
            Already registered?{' '}
            <button
              type="button"
              onClick={onSwitchToLogin}
              className="font-medium text-cyan-400 hover:text-cyan-300"
            >
              Sign in here
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
