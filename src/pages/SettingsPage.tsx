import React, { useEffect, useState } from 'react';
import { CheckCircle2, Cpu, KeyRound, LogOut, Terminal, User, XCircle } from 'lucide-react';
import type { ScannerHealth, StudentUser } from '../../shared/types';
import { apiRequest } from '../api/client';
import { useAuth } from '../context/AuthContext';

export function SettingsPage() {
  const { user, setUser, logout } = useAuth();
  const [fullName, setFullName] = useState(user?.fullName || '');
  const [preferredModel, setPreferredModel] = useState(user?.preferredModel || 'gemini-4-hydrogen');
  const [profileMsg, setProfileMsg] = useState<string | null>(null);
  const [profileErr, setProfileErr] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passMsg, setPassMsg] = useState<string | null>(null);
  const [passErr, setPassErr] = useState<string | null>(null);

  const [scanners, setScanners] = useState<ScannerHealth[]>([]);
  const [aiStatus, setAiStatus] = useState<{ configured: boolean; model: string } | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [scRes, aiRes] = await Promise.all([
          apiRequest<{ scanners: ScannerHealth[] }>('/api/scanners/health'),
          apiRequest<{ configured: boolean; model: string }>('/api/ai/status'),
        ]);
        setScanners(scRes.scanners);
        setAiStatus(aiRes);
      } catch {
        // Non-blocking
      }
    }
    load();
  }, []);

  async function handleSaveProfile(e: React.FormEvent) {
    e.preventDefault();
    setProfileMsg(null);
    setProfileErr(null);
    try {
      const res = await apiRequest<{ user: StudentUser }>('/api/auth/profile', {
        method: 'PUT',
        body: JSON.stringify({ fullName, preferredModel }),
      });
      setUser(res.user);
      setProfileMsg('Account preferences updated.');
    } catch (err) {
      setProfileErr(err instanceof Error ? err.message : 'Failed to update profile.');
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setPassMsg(null);
    setPassErr(null);
    try {
      await apiRequest('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword, confirmPassword }),
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPassMsg('Password changed successfully.');
    } catch (err) {
      setPassErr(err instanceof Error ? err.message : 'Failed to change password.');
    }
  }

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
          Settings
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Manage your student profile, password, AI model preference, and inspect local scanner availability.
        </p>
      </div>

      {/* Profile & Preferences */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form
          onSubmit={handleSaveProfile}
          className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4"
        >
          <div className="flex items-center gap-2 text-slate-100">
            <User className="h-4 w-4 text-cyan-400" />
            <h2 className="font-display text-base font-semibold">Student Profile &amp; Preferences</h2>
          </div>

          {profileErr && (
            <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-3 py-2 text-xs text-rose-200">
              {profileErr}
            </div>
          )}
          {profileMsg && (
            <div className="rounded-lg border border-emerald-800/70 bg-emerald-950/35 px-3 py-2 text-xs text-emerald-200">
              {profileMsg}
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">Full Name</label>
            <input
              type="text"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">Email Address</label>
            <input
              type="email"
              disabled
              value={user?.email || ''}
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a]/50 px-3 py-2 text-sm text-slate-500 cursor-not-allowed"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">Gemini Model Preference</label>
            <select
              value={preferredModel}
              onChange={(e) => setPreferredModel(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            >
              <option value="gemini-4-hydrogen">gemini-4-hydrogen (Balanced Reasoning)</option>
              <option value="gemini-3.1-flash-lite">gemini-3.1-flash-lite (Fast Lightweight)</option>
            </select>
          </div>

          <button
            type="submit"
            className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400"
          >
            Save Profile Preferences
          </button>
        </form>

        {/* Password Change */}
        <form
          onSubmit={handleChangePassword}
          className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4"
        >
          <div className="flex items-center gap-2 text-slate-100">
            <KeyRound className="h-4 w-4 text-cyan-400" />
            <h2 className="font-display text-base font-semibold">Change Password</h2>
          </div>

          {passErr && (
            <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-3 py-2 text-xs text-rose-200">
              {passErr}
            </div>
          )}
          {passMsg && (
            <div className="rounded-lg border border-emerald-800/70 bg-emerald-950/35 px-3 py-2 text-xs text-emerald-200">
              {passMsg}
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">Current Password</label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">New Password</label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">Confirm New Password</label>
            <input
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <button
            type="submit"
            className="rounded-lg border border-slate-700 bg-[#131c31] px-4 py-2 text-xs font-semibold text-slate-100 hover:border-cyan-500/50"
          >
            Update Password
          </button>
        </form>
      </div>

      {/* Gemini Server Configuration Status (No Key Input/Display) */}
      <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <Cpu className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h2 className="font-display text-base font-semibold text-slate-100">
              Gemini AI Server Integration Status
            </h2>
            <p className="text-xs text-slate-400">
              API credentials are managed securely on the server via environment variables and are never exposed to browser JavaScript.
            </p>
          </div>
        </div>
        <div className="font-mono text-xs shrink-0">
          {aiStatus?.configured ? (
            <span className="inline-flex items-center gap-1.5 text-emerald-400">
              <CheckCircle2 className="h-4 w-4" /> Configured ({aiStatus.model})
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-amber-400">
              <XCircle className="h-4 w-4" /> Not Configured on Server
            </span>
          )}
        </div>
      </div>

      {/* Scanner Availability & Windows Installation Instructions */}
      <div className="rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden">
        <div className="border-b border-slate-800 px-6 py-4 flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <h2 className="font-display text-base font-semibold text-slate-100">
            Security Scanner Health &amp; Windows Installation Guide
          </h2>
        </div>

        <div className="divide-y divide-slate-800/80">
          {scanners.map((sc) => (
            <div key={sc.name} className="p-5 space-y-2.5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <p className="text-sm font-medium text-slate-100">{sc.displayName}</p>
                  <p className="text-xs text-slate-400">
                    Languages: {sc.supportedLanguages.join(', ')} · Executable: {sc.executablePath}
                  </p>
                </div>
                <span
                  className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${
                    sc.available ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {sc.available ? (
                    <>
                      <CheckCircle2 className="h-4 w-4" /> Available (v{sc.version})
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4" /> Unavailable
                    </>
                  )}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                <div className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2">
                  <span className="text-slate-500 block mb-0.5">Windows PowerShell:</span>
                  <code className="text-cyan-300 font-mono">{sc.installInstructionsWindows}</code>
                </div>
                <div className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2">
                  <span className="text-slate-500 block mb-0.5">Linux / macOS:</span>
                  <code className="text-slate-300 font-mono">{sc.installInstructionsLinux}</code>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Session Sign Out */}
      <div className="flex justify-end">
        <button
          type="button"
          onClick={() => logout()}
          className="inline-flex items-center gap-2 rounded-lg border border-rose-900/70 bg-rose-950/30 px-4 py-2 text-xs font-medium text-rose-200 hover:bg-rose-950/50"
        >
          <LogOut className="h-4 w-4" />
          <span>Sign Out of SecureLens</span>
        </button>
      </div>
    </div>
  );
}
