import { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  GitBranch,
  GitCommitHorizontal,
  Link2,
  Play,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type { Project, ScannerHealth, ScanSession } from '../../shared/types';
import { apiRequest } from '../api/client';
import { GitHubImportPanel } from '../components/GitHubImportPanel';
import type { NavSection } from '../layouts/AppShell';

export function NewScanPage({
  initialProjectId,
  onNavigate,
}: {
  initialProjectId?: string;
  onNavigate: (section: NavSection, context?: { projectId?: string; scanId?: string }) => void;
}) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scanners, setScanners] = useState<ScannerHealth[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>(initialProjectId || '');
  const [selectedScanners, setSelectedScanners] = useState<string[]>([
    'custom',
    'bandit',
    'semgrep',
    'gitleaks',
    'eslint',
    'osv',
  ]);
  const [running, setRunning] = useState(false);
  const [lastScan, setLastScan] = useState<ScanSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showGitHubImport, setShowGitHubImport] = useState(false);
  const scanInFlightRef = useRef(false);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [projRes, scanHealthRes] = await Promise.all([
          apiRequest<{ projects: Project[] }>('/api/projects'),
          apiRequest<{ scanners: ScannerHealth[] }>('/api/scanners/health'),
        ]);
        if (!active) return;
        setProjects(projRes.projects);
        setScanners(scanHealthRes.scanners);
        if (!selectedProjectId && projRes.projects.length > 0) {
          setSelectedProjectId(projRes.projects[0].id);
        }
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load projects and scanners.');
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggleScanner(name: string) {
    setSelectedScanners((prev) =>
      prev.includes(name) ? prev.filter((s) => s !== name) : [...prev, name]
    );
  }

  async function handleStartScan() {
    if (scanInFlightRef.current) return;
    if (!selectedProjectId) {
      setError('Select a project first.');
      return;
    }
    if (selectedScanners.length === 0) {
      setError('Select at least one security scanner.');
      return;
    }
    scanInFlightRef.current = true;
    setRunning(true);
    setError(null);
    setLastScan(null);

    try {
      const res = await apiRequest<{ scan: ScanSession }>('/api/scans', {
        method: 'POST',
        body: JSON.stringify({
          projectId: selectedProjectId,
          scanners: selectedScanners,
        }),
      });
      setLastScan(res.scan);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to execute security scan.');
    } finally {
      scanInFlightRef.current = false;
      setRunning(false);
    }
  }

  const activeProject = projects.find((p) => p.id === selectedProjectId);

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
            New Security Scan
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Run available static analysis, secret detection, and dependency vulnerability scanners in an isolated temporary workspace.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowGitHubImport((prev) => !prev)}
          className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 whitespace-nowrap shrink-0"
        >
          <Link2 className="h-3.5 w-3.5" />
          <span>Import GitHub Repo</span>
        </button>
      </div>

      {showGitHubImport && (
        <GitHubImportPanel
          onClose={() => setShowGitHubImport(false)}
          onImported={(project) => {
            setProjects((prev) => [project, ...prev.filter((p) => p.id !== project.id)]);
            setSelectedProjectId(project.id);
            setShowGitHubImport(false);
          }}
        />
      )}

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <div className="h-56 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      ) : projects.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-8 text-center space-y-3">
          <p className="text-sm text-slate-300">You need to create a project, upload code, or import a GitHub repository before scanning.</p>
          <div className="flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => setShowGitHubImport(true)}
              className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20"
            >
              Import GitHub Repo
            </button>
            <button
              type="button"
              onClick={() => onNavigate('projects')}
              className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400"
            >
              Go to Projects
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-5">
            <div className="space-y-2">
              <label htmlFor="scan-project" className="block text-xs font-medium text-slate-300">
                Target Project
              </label>
              <select
                id="scan-project"
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2.5 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.fileCount} files · {p.primaryLanguage || 'No language detected'})
                  </option>
                ))}
              </select>
              {activeProject && activeProject.importMethod === 'github' && activeProject.githubRepoUrl && (
                <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono pt-1">
                  <span className="text-cyan-300">{activeProject.githubRepoUrl}</span>
                  {activeProject.githubBranch && (
                    <span className="inline-flex items-center gap-1">
                      <GitBranch className="h-3 w-3 text-slate-500" />
                      {activeProject.githubBranch}
                    </span>
                  )}
                  {activeProject.githubCommitSha && (
                    <span className="inline-flex items-center gap-1">
                      <GitCommitHorizontal className="h-3 w-3 text-slate-500" />
                      {activeProject.githubCommitSha.slice(0, 7)}
                    </span>
                  )}
                </div>
              )}
              {activeProject && activeProject.fileCount === 0 && (
                <p className="text-xs text-amber-300">
                  This project currently has 0 files. Upload source files on the Projects page before scanning.
                </p>
              )}
            </div>

            <div className="space-y-3">
              <p className="text-xs font-medium text-slate-300">Security Scanning Engines</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scanners.map((sc) => {
                  const checked = selectedScanners.includes(sc.name);
                  return (
                    <label
                      key={sc.name}
                      className={`flex items-start gap-3 rounded-lg border p-3.5 cursor-pointer transition-colors ${
                        checked
                          ? 'border-cyan-500/40 bg-cyan-500/5'
                          : 'border-slate-800 bg-[#080d1a]/60 hover:border-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleScanner(sc.name)}
                        className="mt-1 accent-cyan-500"
                      />
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium text-slate-200">{sc.displayName}</span>
                          <span
                            className={`text-xs font-medium whitespace-nowrap ${
                              sc.available ? 'text-emerald-400' : 'text-amber-400'
                            }`}
                          >
                            {sc.available ? `Ready (v${sc.version})` : 'Missing CLI'}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400">{sc.description}</p>
                        {!sc.available && (
                          <p className="font-mono text-[11px] text-slate-400 bg-[#080d1a] rounded px-2 py-1 border border-slate-800">
                            {sc.installInstructionsWindows}
                          </p>
                        )}
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="flex items-center justify-between gap-4 border-t border-slate-800 pt-4">
              <p className="text-xs text-slate-400">
                Scans run statically without executing uploaded code. Unavailable external tools are reported transparently without failing other scanners.
              </p>
              <button
                type="button"
                disabled={running || !activeProject || activeProject.fileCount === 0}
                onClick={handleStartScan}
                className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
              >
                <Play className="h-4 w-4" />
                <span>{running ? 'Running Scanners...' : 'Start Security Scan'}</span>
              </button>
            </div>
          </div>

          {/* Scan Execution Results */}
          {lastScan && (
            <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <ShieldCheck className="h-6 w-6 text-cyan-400 shrink-0" />
                  <div>
                    <h2 className="font-display text-lg font-semibold text-slate-100">
                      Scan Complete · Status: <span className="capitalize">{lastScan.status}</span>
                    </h2>
                    <p className="text-xs text-slate-400 font-mono tabular-nums">
                      Total Normalized Findings: {lastScan.totalFindings} (Critical: {lastScan.criticalCount}, High: {lastScan.highCount}, Medium: {lastScan.mediumCount}, Low: {lastScan.lowCount})
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate('findings', { projectId: lastScan.projectId, scanId: lastScan.id })}
                  className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 whitespace-nowrap shrink-0"
                >
                  Inspect {lastScan.totalFindings} Finding(s)
                </button>
              </div>

              <div className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-[#080d1a]">
                {(lastScan.scannerResults || []).map((sr) => (
                  <div key={sr.scannerName} className="px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-2.5">
                      {sr.status === 'completed' ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                      ) : sr.status === 'unavailable' ? (
                        <AlertCircle className="h-4 w-4 text-amber-400 shrink-0" />
                      ) : (
                        <XCircle className="h-4 w-4 text-rose-400 shrink-0" />
                      )}
                      <span className="font-medium text-slate-200 uppercase">{sr.scannerName}</span>
                      <span className="text-slate-500">{sr.version ? `v${sr.version}` : ''}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-4 text-slate-400 font-mono tabular-nums">
                      <span className="capitalize">{sr.status}</span>
                      <span>{sr.findingsCount} raw</span>
                      <span>{sr.durationMs}ms</span>
                      {sr.errorMessage && (
                        <span className="text-amber-300 font-sans">{sr.errorMessage}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {lastScan.diagnostics && lastScan.diagnostics.length > 0 && (
                <div className="rounded-lg border border-amber-800/60 bg-amber-950/20 p-4 space-y-2.5">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-amber-400 shrink-0" />
                    <h3 className="text-xs font-semibold text-amber-200 uppercase tracking-wider">
                      Syntax &amp; Parse Diagnostics ({lastScan.diagnostics.length})
                    </h3>
                  </div>
                  <p className="text-xs text-slate-400">
                    Code syntax issues were detected during static analysis. Scanners recovered where possible to continue evaluating remaining lines.
                  </p>
                  <div className="divide-y divide-amber-900/40 rounded border border-amber-900/40 bg-[#080d1a]">
                    {lastScan.diagnostics.map((diag) => {
                      const scannersList =
                        diag.contributingScanners && diag.contributingScanners.length > 0
                          ? diag.contributingScanners
                          : [diag.scannerName];
                      return (
                        <div key={diag.id} className="px-3.5 py-2.5 text-xs space-y-1">
                          <div className="flex flex-wrap items-center gap-2 font-mono">
                            <span className="text-amber-300">
                              {diag.filePath}:{diag.line}
                              {diag.column ? `:${diag.column}` : ''}
                            </span>
                            <span className="text-slate-600">·</span>
                            <span className="uppercase text-slate-400">
                              {scannersList.join(' + ')}
                            </span>
                            <span className="text-slate-600">·</span>
                            <span className="text-slate-400">{diag.kind.replace(/_/g, ' ')}</span>
                          </div>
                          <p className="text-slate-300">{diag.message}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
