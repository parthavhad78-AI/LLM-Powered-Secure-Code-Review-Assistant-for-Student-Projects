import React, { useEffect, useRef, useState } from 'react';
import {
  CheckCircle2,
  GitBranch,
  GitCommitHorizontal,
  Link2,
  Loader2,
  Lock,
  RefreshCw,
  ShieldCheck,
  Unlink,
  X,
} from 'lucide-react';
import type {
  GitHubRepoValidation,
  GitHubStatus,
  Project,
} from '../../shared/types';
import { apiRequest } from '../api/client';

export function GitHubImportPanel({
  targetProjectId,
  onImported,
  onClose,
}: {
  targetProjectId?: string;
  onImported: (project: Project, importedFilesCount: number) => void;
  onClose?: () => void;
}) {
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [repoUrl, setRepoUrl] = useState('');
  const [projectName, setProjectName] = useState('');
  const [selectedBranch, setSelectedBranch] = useState('');
  const [validation, setValidation] = useState<GitHubRepoValidation | null>(null);
  const [validating, setValidating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [connectingOAuth, setConnectingOAuth] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  async function loadGitHubStatus() {
    try {
      const res = await apiRequest<{ status: GitHubStatus }>('/api/github/status');
      setStatus(res.status);
    } catch {
      // Status check is advisory
    }
  }

  useEffect(() => {
    loadGitHubStatus();

    function handleOAuthMessage(event: MessageEvent) {
      if (!event.data || typeof event.data !== 'object') return;
      if (event.data.type === 'GITHUB_OAUTH_SUCCESS') {
        setConnectingOAuth(false);
        setError(null);
        setInfoMsg(`Connected GitHub account @${event.data.username || 'user'}.`);
        loadGitHubStatus();
      } else if (event.data.type === 'GITHUB_OAUTH_ERROR') {
        setConnectingOAuth(false);
        setError(String(event.data.error || 'GitHub authorization failed.'));
      }
    }

    window.addEventListener('message', handleOAuthMessage);
    return () => {
      window.removeEventListener('message', handleOAuthMessage);
      abortRef.current?.abort();
    };
  }, []);

  async function handleConnectGitHub() {
    setError(null);
    setInfoMsg(null);
    setConnectingOAuth(true);
    try {
      const res = await apiRequest<{ authUrl: string }>('/api/github/oauth/url');
      const popup = window.open(
        res.authUrl,
        'securelens_github_oauth',
        'width=620,height=720,resizable=yes,scrollbars=yes'
      );
      if (!popup) {
        setConnectingOAuth(false);
        setError('Browser blocked the GitHub OAuth popup. Allow popups for this site and try again.');
      }
    } catch (err) {
      setConnectingOAuth(false);
      setError(err instanceof Error ? err.message : 'Unable to start GitHub OAuth connection.');
    }
  }

  async function handleDisconnectGitHub() {
    setError(null);
    setInfoMsg(null);
    try {
      const res = await apiRequest<{ status: GitHubStatus }>('/api/github/disconnect', {
        method: 'POST',
      });
      setStatus(res.status);
      setInfoMsg('Disconnected GitHub OAuth credentials.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to disconnect GitHub.');
    }
  }

  async function handleValidate(overrideBranch?: string) {
    if (!repoUrl.trim()) {
      setError('Enter a GitHub repository URL (e.g., https://github.com/owner/repo).');
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setValidating(true);
    setError(null);
    setInfoMsg(null);

    try {
      const res = await apiRequest<{ validation: GitHubRepoValidation }>('/api/github/validate', {
        method: 'POST',
        signal: controller.signal,
        body: JSON.stringify({
          repoUrl: repoUrl.trim(),
          branch: overrideBranch || selectedBranch || undefined,
        }),
      });
      setValidation(res.validation);
      setSelectedBranch(res.validation.selectedBranch);
      if (!projectName.trim()) {
        setProjectName(`${res.validation.owner}/${res.validation.repo}`);
      }
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') return;
      setValidation(null);
      setError(err instanceof Error ? err.message : 'Failed to validate GitHub repository.');
    } finally {
      setValidating(false);
    }
  }

  async function handleImport(e: React.FormEvent) {
    e.preventDefault();
    if (!repoUrl.trim()) {
      setError('Enter a GitHub repository URL first.');
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setImporting(true);
    setError(null);
    setInfoMsg(null);

    try {
      const res = await apiRequest<{
        project: Project;
        validation: GitHubRepoValidation;
        importedFilesCount: number;
      }>('/api/github/import', {
        method: 'POST',
        signal: controller.signal,
        body: JSON.stringify({
          projectId: targetProjectId || undefined,
          projectName: projectName.trim() || undefined,
          repoUrl: repoUrl.trim(),
          branch: selectedBranch || undefined,
        }),
      });
      onImported(res.project, res.importedFilesCount);
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') {
        setInfoMsg('GitHub import cancelled.');
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to import GitHub repository.');
    } finally {
      setImporting(false);
    }
  }

  function handleCancelActive() {
    abortRef.current?.abort();
    setValidating(false);
    setImporting(false);
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-100">
            Import GitHub Repository
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            Validate a public or authorized private repository on github.com and import a clean source archive without executing repository scripts.
          </p>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close GitHub import panel"
            className="rounded-lg border border-slate-800 p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Private Repository OAuth Connection Status */}
      {status && (
        <div className="rounded-lg border border-slate-800 bg-[#080d1a] px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5 text-slate-300">
            <Lock className="h-4 w-4 text-cyan-400 shrink-0" />
            {status.connected ? (
              <span>
                GitHub OAuth connected as{' '}
                <span className="font-mono font-semibold text-emerald-300">@{status.username}</span>{' '}
                (private repositories enabled).
              </span>
            ) : status.oauthConfigured ? (
              <span>
                Public repositories import without sign-in. Connect GitHub OAuth to access private repositories.
              </span>
            ) : (
              <span>
                Public repositories import directly. Private repository OAuth requires{' '}
                <span className="font-mono text-slate-200">GITHUB_CLIENT_ID</span> &amp;{' '}
                <span className="font-mono text-slate-200">GITHUB_CLIENT_SECRET</span> on the server.
              </span>
            )}
          </div>

          <div className="shrink-0">
            {status.connected ? (
              <button
                type="button"
                onClick={handleDisconnectGitHub}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                <Unlink className="h-3.5 w-3.5" />
                <span>Disconnect</span>
              </button>
            ) : status.oauthConfigured ? (
              <button
                type="button"
                disabled={connectingOAuth}
                onClick={handleConnectGitHub}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
              >
                <Link2 className="h-3.5 w-3.5" />
                <span>{connectingOAuth ? 'Waiting for GitHub...' : 'Connect GitHub'}</span>
              </button>
            ) : null}
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-2.5 text-xs text-rose-200">
          {error}
        </div>
      )}
      {infoMsg && (
        <div className="rounded-lg border border-emerald-800/70 bg-emerald-950/35 px-4 py-2.5 text-xs text-emerald-200">
          {infoMsg}
        </div>
      )}

      <form onSubmit={handleImport} className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-7 space-y-1.5">
            <label htmlFor="gh-repo-url" className="block text-xs font-medium text-slate-300">
              GitHub Repository URL
            </label>
            <input
              id="gh-repo-url"
              type="url"
              required
              value={repoUrl}
              onChange={(e) => {
                setRepoUrl(e.target.value);
                setValidation(null);
              }}
              placeholder="https://github.com/owner/repository"
              className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {!targetProjectId && (
            <div className="md:col-span-3 space-y-1.5">
              <label htmlFor="gh-proj-name" className="block text-xs font-medium text-slate-300">
                Project Name (Optional)
              </label>
              <input
                id="gh-proj-name"
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="owner/repository"
                className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          )}

          <div className={`${targetProjectId ? 'md:col-span-5' : 'md:col-span-2'} flex items-center gap-2`}>
            <button
              type="button"
              disabled={validating || importing || !repoUrl.trim()}
              onClick={() => handleValidate()}
              className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-[#131c31] px-3 py-2 text-xs font-medium text-slate-200 hover:border-cyan-500/50 disabled:opacity-50 whitespace-nowrap"
            >
              {validating ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
              )}
              <span>{validating ? 'Validating...' : 'Validate'}</span>
            </button>
          </div>
        </div>

        {validation && (
          <div className="rounded-lg border border-cyan-500/30 bg-[#080d1a] p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                <span className="font-mono text-sm font-semibold text-slate-100">
                  {validation.owner}/{validation.repo}
                </span>
                <span className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300">
                  {validation.isPrivate ? 'Private' : 'Public'}
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                <GitCommitHorizontal className="h-3.5 w-3.5 text-cyan-400" />
                <span>{validation.commitSha.slice(0, 12)}</span>
              </div>
            </div>

            {validation.description && (
              <p className="text-xs text-slate-400">{validation.description}</p>
            )}

            <div className="flex flex-col sm:flex-row sm:items-center gap-3 pt-1">
              <div className="flex items-center gap-2">
                <GitBranch className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                <label htmlFor="gh-branch-select" className="text-xs text-slate-300">
                  Branch:
                </label>
                <select
                  id="gh-branch-select"
                  value={selectedBranch}
                  onChange={(e) => {
                    const nextBranch = e.target.value;
                    setSelectedBranch(nextBranch);
                    handleValidate(nextBranch);
                  }}
                  className="rounded-lg border border-slate-700 bg-[#0e1526] px-2.5 py-1.5 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
                >
                  {validation.branches.map((b: string) => (
                    <option key={b} value={b}>
                      {b} {b === validation.defaultBranch ? '(default)' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
          {(validating || importing) && (
            <button
              type="button"
              onClick={handleCancelActive}
              className="rounded-lg border border-slate-700 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              Cancel Request
            </button>
          )}
          <button
            type="submit"
            disabled={importing || validating || !repoUrl.trim()}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 whitespace-nowrap"
          >
            {importing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            <span>{importing ? 'Importing Repository...' : 'Import Repository'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
