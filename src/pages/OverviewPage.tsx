import { useEffect, useState } from 'react';
import { ArrowRight, CheckCircle2, FolderGit2, Play, ShieldAlert, Wrench } from 'lucide-react';
import type { DashboardStats, ScannerHealth } from '../../shared/types';
import { apiRequest } from '../api/client';
import {
  CategoryBarChart,
  RemediationProgressMeter,
  ScanActivityChart,
  SeverityDistributionChart,
} from '../components/Charts';
import type { NavSection } from '../layouts/AppShell';

export function OverviewPage({
  onNavigate,
}: {
  onNavigate: (section: NavSection, context?: { scanId?: string; projectId?: string }) => void;
}) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [scanners, setScanners] = useState<ScannerHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [dashRes, scannerRes] = await Promise.all([
          apiRequest<{ stats: DashboardStats }>('/api/dashboard/stats'),
          apiRequest<{ scanners: ScannerHealth[] }>('/api/scanners/health'),
        ]);
        if (!active) return;
        setStats(dashRes.stats);
        setScanners(scannerRes.scanners);
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load dashboard data.');
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
          ))}
        </div>
        <div className="h-64 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="rounded-xl border border-rose-800/70 bg-rose-950/30 p-6 text-sm text-rose-200">
        {error || 'Unable to load overview statistics.'}
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header & Quick CTA */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
            Security Overview
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Live database metrics across your uploaded student projects, static scans, and validated fixes.
          </p>
        </div>
        {stats.totalProjects === 0 && (
          <button
            type="button"
            onClick={() => onNavigate('projects')}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-colors whitespace-nowrap shrink-0"
          >
            <FolderGit2 className="h-4 w-4" />
            <span>Create First Project</span>
          </button>
        )}
      </div>

      {/* Primary KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Projects</span>
            <FolderGit2 className="h-4 w-4 text-slate-500" />
          </div>
          <p className="font-mono text-3xl font-semibold text-slate-100 tabular-nums">
            {stats.totalProjects}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Scans</span>
            <Play className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="font-mono text-3xl font-semibold text-slate-100 tabular-nums">
            {stats.totalScans}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Vulnerabilities</span>
            <ShieldAlert className="h-4 w-4 text-orange-400" />
          </div>
          <p className="font-mono text-3xl font-semibold text-slate-100 tabular-nums">
            {stats.totalVulnerabilities}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Remediated Findings</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <p className="font-mono text-3xl font-semibold text-emerald-400 tabular-nums">
            {stats.remediatedFindings}
          </p>
        </div>
      </div>

      {/* Severity Breakdown & Remediation Progress */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-base font-semibold text-slate-100">
              Vulnerability Severity Distribution
            </h2>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400 hover:text-cyan-300 whitespace-nowrap"
            >
              <span>Inspect Findings</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <SeverityDistributionChart stats={stats} />
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 flex flex-col justify-center">
          <RemediationProgressMeter
            total={stats.totalVulnerabilities}
            remediated={stats.remediatedFindings}
          />
        </div>
      </div>

      {/* Category Distribution & Scan Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4">
          <h2 className="font-display text-base font-semibold text-slate-100">
            Findings by Category
          </h2>
          <CategoryBarChart data={stats.findingsByCategory} />
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4">
          <h2 className="font-display text-base font-semibold text-slate-100">
            Scan Activity Over Time
          </h2>
          <ScanActivityChart data={stats.scanActivity} />
        </div>
      </div>

      {/* Recent Scans & Scanner Availability */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
            <h2 className="font-display text-base font-semibold text-slate-100">
              Recent Scan Activity
            </h2>
          </div>

          {stats.recentScans.length === 0 ? (
            <div className="p-8 text-center space-y-3">
              <p className="text-sm text-slate-400">
                No scans have been executed yet. Upload a project and run your first static scan.
              </p>
              <button
                type="button"
                onClick={() => onNavigate('new-scan')}
                className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 transition-colors"
              >
                Start First Scan
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-400">
                    <th className="px-5 py-3 font-medium">Project</th>
                    <th className="px-5 py-3 font-medium">Type</th>
                    <th className="px-5 py-3 font-medium">Status</th>
                    <th className="px-5 py-3 font-medium text-right">Findings</th>
                    <th className="px-5 py-3 font-medium text-right">Started</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {stats.recentScans.map((scan) => (
                    <tr
                      key={scan.id}
                      onClick={() => onNavigate('findings', { projectId: scan.projectId })}
                      className="hover:bg-slate-800/30 cursor-pointer transition-colors"
                    >
                      <td className="px-5 py-3 font-medium text-slate-200">{scan.projectName}</td>
                      <td className="px-5 py-3 text-xs text-slate-400 capitalize">{scan.triggerType}</td>
                      <td className="px-5 py-3 text-xs font-medium capitalize text-slate-300">
                        {scan.status}
                      </td>
                      <td className="px-5 py-3 text-right font-mono tabular-nums text-slate-200">
                        {scan.totalFindings}
                      </td>
                      <td className="px-5 py-3 text-right font-mono text-xs tabular-nums text-slate-400">
                        {new Date(scan.startedAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
            <h2 className="font-display text-base font-semibold text-slate-100">
              Scanner Availability
            </h2>
            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300"
            >
              Details
            </button>
          </div>
          <div className="divide-y divide-slate-800/70">
            {scanners.map((sc) => (
              <div key={sc.name} className="px-5 py-3 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate">{sc.displayName}</p>
                  <p className="font-mono text-xs text-slate-500 truncate">
                    {sc.available ? `v${sc.version}` : 'Not installed'}
                  </p>
                </div>
                <span
                  className={`text-xs font-medium whitespace-nowrap ${
                    sc.available ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {sc.available ? 'Ready' : 'Unavailable'}
                </span>
              </div>
            ))}
          </div>
          <div className="border-t border-slate-800 px-5 py-3 text-xs text-slate-400 flex items-center gap-2">
            <Wrench className="h-3.5 w-3.5 text-slate-500 shrink-0" />
            <span>Missing external CLI tools show setup commands in Settings.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
