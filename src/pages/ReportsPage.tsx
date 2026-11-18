import React, { useEffect, useState } from 'react';
import { Download, FileBarChart2, FileSpreadsheet, FileText } from 'lucide-react';
import type { Project, ReportRecord } from '../../shared/types';
import { apiRequest } from '../api/client';

export function ReportsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [format, setFormat] = useState<'pdf' | 'csv'>('pdf');
  const [title, setTitle] = useState('');
  const [generating, setGenerating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    try {
      const [projRes, repRes] = await Promise.all([
        apiRequest<{ projects: Project[] }>('/api/projects'),
        apiRequest<{ reports: ReportRecord[] }>('/api/reports'),
      ]);
      setProjects(projRes.projects);
      setReports(repRes.reports);
      if (!selectedProjectId && projRes.projects.length > 0) {
        setSelectedProjectId(projRes.projects[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedProjectId) return;
    setGenerating(true);
    setError(null);
    try {
      const res = await apiRequest<{ report: ReportRecord }>('/api/reports', {
        method: 'POST',
        body: JSON.stringify({
          projectId: selectedProjectId,
          format,
          title: title.trim() || undefined,
        }),
      });
      setTitle('');
      setReports((prev) => [res.report, ...prev]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report.');
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
          Security Assessment Reports
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Export downloadable PDF or CSV security assessment reports containing scanner telemetry, findings, AI advisory notes, and validation outcomes.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <div className="h-64 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      ) : (
        <>
          <form
            onSubmit={handleGenerate}
            className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4"
          >
            <h2 className="font-display text-base font-semibold text-slate-100">
              Generate New Assessment Report
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Project</label>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  required
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                >
                  {projects.length === 0 ? (
                    <option value="">No projects available</option>
                  ) : (
                    projects.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))
                  )}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Export Format</label>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value as 'pdf' | 'csv')}
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                >
                  <option value="pdf">PDF Assessment Report</option>
                  <option value="csv">CSV Findings Spreadsheet</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">
                  Report Title (Optional)
                </label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g., Milestone 2 Audit"
                  className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={generating || !selectedProjectId}
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 whitespace-nowrap"
            >
              <FileBarChart2 className="h-4 w-4" />
              <span>{generating ? 'Generating Report...' : 'Generate Report'}</span>
            </button>
          </form>

          <div className="rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden">
            <div className="border-b border-slate-800 px-6 py-4">
              <h2 className="font-display text-base font-semibold text-slate-100">
                Generated Reports ({reports.length})
              </h2>
            </div>

            {reports.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-500">
                No reports generated yet. Generate a PDF or CSV report above after scanning a project.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/70">
                {reports.map((rep) => (
                  <div
                    key={rep.id}
                    className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      {rep.format === 'pdf' ? (
                        <FileText className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
                      ) : (
                        <FileSpreadsheet className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
                      )}
                      <div className="min-w-0 space-y-1">
                        <p className="text-sm font-medium text-slate-100 truncate">{rep.title}</p>
                        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                          <span>{rep.projectName}</span>
                          <span>·</span>
                          <span className="uppercase">{rep.format}</span>
                          <span>·</span>
                          <span>{rep.summary.totalFindings ?? 0} findings</span>
                          <span>·</span>
                          <span>{rep.summary.remediated ?? 0} remediated</span>
                          <span>·</span>
                          <span>{new Date(rep.createdAt).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>

                    <a
                      href={`/api/reports/${rep.id}/download`}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#080d1a] px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-cyan-500/50 whitespace-nowrap shrink-0"
                    >
                      <Download className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Download {rep.format.toUpperCase()}</span>
                    </a>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
