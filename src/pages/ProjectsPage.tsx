import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Edit3,
  FileCode2,
  FolderPlus,
  GitBranch,
  GitCommitHorizontal,
  Link2,
  Play,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-react';
import type { GitHubRefreshResult, Project, ProjectFile, ScanSession } from '../../shared/types';
import { apiRequest } from '../api/client';
import { GitHubImportPanel } from '../components/GitHubImportPanel';
import type { NavSection } from '../layouts/AppShell';

export function ProjectsPage({
  onNavigate,
}: {
  onNavigate: (section: NavSection, context?: { projectId?: string; scanId?: string }) => void;
}) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{
    project: Project;
    files: ProjectFile[];
    scans: ScanSession[];
    unsupportedLanguages: string[];
  } | null>(null);
  const [viewingFile, setViewingFile] = useState<{ relativePath: string; content: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Create/Edit modal state
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [saving, setSaving] = useState(false);

  // Delete confirmation state
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null);

  // Upload & GitHub state
  const [uploading, setUploading] = useState(false);
  const [showGitHubImport, setShowGitHubImport] = useState(false);
  const [refreshingGitHub, setRefreshingGitHub] = useState(false);

  async function loadProjects(selectId?: string) {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<{ projects: Project[] }>('/api/projects');
      setProjects(res.projects);
      const nextId = selectId || selectedProjectId || res.projects[0]?.id || null;
      setSelectedProjectId(nextId);
      if (nextId) {
        await loadDetail(nextId);
      } else {
        setDetail(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load projects.');
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(projectId: string) {
    setViewingFile(null);
    try {
      const res = await apiRequest<{
        project: Project;
        files: ProjectFile[];
        scans: ScanSession[];
        unsupportedLanguages: string[];
      }>(`/api/projects/${projectId}`);
      setDetail(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load project details.');
    }
  }

  useEffect(() => {
    loadProjects();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleSaveProject(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSuccessMsg(null);
    try {
      if (editingProject) {
        const res = await apiRequest<{ project: Project }>(`/api/projects/${editingProject.id}`, {
          method: 'PUT',
          body: JSON.stringify({ name: formName, description: formDesc }),
        });
        setEditingProject(null);
        setShowCreateForm(false);
        setSuccessMsg(`Updated project "${res.project.name}".`);
        await loadProjects(res.project.id);
      } else {
        const res = await apiRequest<{ project: Project }>('/api/projects', {
          method: 'POST',
          body: JSON.stringify({ name: formName, description: formDesc }),
        });
        setShowCreateForm(false);
        setFormName('');
        setFormDesc('');
        setSuccessMsg(`Created project "${res.project.name}". Upload a ZIP or source files to begin.`);
        await loadProjects(res.project.id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save project.');
    } finally {
      setSaving(false);
    }
  }

  async function handleDeleteProject() {
    if (!deleteTarget) return;
    setError(null);
    try {
      await apiRequest(`/api/projects/${deleteTarget.id}`, { method: 'DELETE' });
      const deletedName = deleteTarget.name;
      setDeleteTarget(null);
      if (selectedProjectId === deleteTarget.id) {
        setSelectedProjectId(null);
      }
      setSuccessMsg(`Deleted project "${deletedName}".`);
      await loadProjects();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete project.');
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    if (!selectedProjectId || !e.target.files || e.target.files.length === 0) return;
    setUploading(true);
    setError(null);
    setSuccessMsg(null);
    const formData = new FormData();
    Array.from(e.target.files).forEach((file) => {
      formData.append('files', file);
    });
    formData.append('replace', 'true');

    try {
      const res = await apiRequest<{ project: Project; uploadedCount: number }>(
        `/api/projects/${selectedProjectId}/upload`,
        {
          method: 'POST',
          body: formData,
        }
      );
      setSuccessMsg(`Uploaded ${res.uploadedCount} source file(s) safely into "${res.project.name}".`);
      await loadProjects(selectedProjectId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload rejected.');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  }

  async function handleViewFile(relPath: string) {
    if (!selectedProjectId) return;
    try {
      const res = await apiRequest<{ relativePath: string; content: string }>(
        `/api/projects/${selectedProjectId}/file?path=${encodeURIComponent(relPath)}`
      );
      setViewingFile(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to view file.');
    }
  }

  async function handleRefreshFromGitHub() {
    if (!selectedProjectId) return;
    setRefreshingGitHub(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await apiRequest<GitHubRefreshResult>(
        `/api/github/projects/${selectedProjectId}/refresh`,
        { method: 'POST' }
      );
      if (res.changed) {
        setSuccessMsg(
          `Updated from GitHub (${res.branch} @ ${res.latestCommitSha.slice(0, 7)}, ${res.importedCount} files). Previous scan snapshots and findings remain preserved.`
        );
      } else {
        setSuccessMsg(
          `Repository is already up to date on branch ${res.branch} (${res.latestCommitSha.slice(0, 7)}).`
        );
      }
      await loadProjects(selectedProjectId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh repository from GitHub.');
    } finally {
      setRefreshingGitHub(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
            Projects
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Create isolated student code workspaces and upload ZIP archives or source files safely.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => {
              setShowCreateForm(false);
              setShowGitHubImport((prev) => !prev);
            }}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 transition-colors whitespace-nowrap shrink-0"
          >
            <Link2 className="h-4 w-4" />
            <span>Import from GitHub</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setShowGitHubImport(false);
              setEditingProject(null);
              setFormName('');
              setFormDesc('');
              setShowCreateForm(true);
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 transition-colors whitespace-nowrap shrink-0"
          >
            <FolderPlus className="h-4 w-4" />
            <span>New Project</span>
          </button>
        </div>
      </div>

      {showGitHubImport && (
        <GitHubImportPanel
          onClose={() => setShowGitHubImport(false)}
          onImported={async (project, importedCount) => {
            setShowGitHubImport(false);
            setSuccessMsg(
              `Imported ${importedCount} file(s) from ${project.githubRepoUrl} (${project.githubBranch} @ ${project.githubCommitSha?.slice(0, 7)}).`
            );
            await loadProjects(project.id);
          }}
        />
      )}

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}
      {successMsg && (
        <div className="rounded-lg border border-emerald-800/70 bg-emerald-950/35 px-4 py-3 text-sm text-emerald-200">
          {successMsg}
        </div>
      )}

      {/* Create / Edit Form */}
      {showCreateForm && (
        <form
          onSubmit={handleSaveProject}
          className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4"
        >
          <h2 className="font-display text-base font-semibold text-slate-100">
            {editingProject ? 'Edit Project Details' : 'Create New Project'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-300">Project Name</label>
              <input
                type="text"
                required
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="e.g., Campus Portal Backend"
                className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-300">Description</label>
              <input
                type="text"
                value={formDesc}
                onChange={(e) => setFormDesc(e.target.value)}
                placeholder="Short summary of your project stack"
                className="w-full rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 whitespace-nowrap"
            >
              {saving ? 'Saving...' : editingProject ? 'Save Changes' : 'Create Project'}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowCreateForm(false);
                setEditingProject(null);
              }}
              className="rounded-lg border border-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800/60 whitespace-nowrap"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 px-4">
          <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4">
            <h3 className="font-display text-base font-semibold text-slate-100">
              Delete "{deleteTarget.name}"?
            </h3>
            <p className="text-sm text-slate-400">
              This permanently removes the project source files, scan history, findings, and AI analyses.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                className="rounded-lg border border-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteProject}
                className="rounded-lg bg-rose-600 px-4 py-2 text-xs font-semibold text-white hover:bg-rose-500"
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="h-64 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      ) : projects.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-12 text-center space-y-3">
          <p className="text-base font-medium text-slate-200">No projects created yet</p>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            Create a project workspace and upload your Python, JavaScript, TypeScript, or dependency manifest files to run static security scans.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Project List */}
          <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-[#0e1526] divide-y divide-slate-800/80">
            {projects.map((p) => {
              const active = p.id === selectedProjectId;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => {
                    setSelectedProjectId(p.id);
                    loadDetail(p.id);
                  }}
                  className={`w-full text-left p-4 transition-colors ${
                    active ? 'bg-cyan-500/8' : 'hover:bg-slate-800/30'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className={`font-medium text-sm truncate ${active ? 'text-cyan-300' : 'text-slate-100'}`}>
                      {p.name}
                    </p>
                    <span className="font-mono text-xs text-slate-400 tabular-nums shrink-0">
                      {p.fileCount} files
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-400 truncate">
                    {p.primaryLanguage || 'No files uploaded'} · {p.openFindingsCount ?? 0} open findings
                  </p>
                </button>
              );
            })}
          </div>

          {/* Selected Project Details */}
          <div className="lg:col-span-8 space-y-6">
            {detail && (
              <>
                <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div className="space-y-1 min-w-0">
                      <h2 className="font-display text-xl font-semibold text-slate-100">
                        {detail.project.name}
                      </h2>
                      <p className="text-sm text-slate-400">
                        {detail.project.description || 'No description provided.'}
                      </p>
                      <div className="pt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                        <span className="rounded border border-slate-700 bg-[#080d1a] px-2 py-0.5 font-medium text-slate-300 uppercase text-[10px]">
                          {detail.project.importMethod === 'github'
                            ? 'GitHub'
                            : detail.project.importMethod === 'zip'
                              ? 'ZIP'
                              : 'Upload'}
                        </span>
                        <span>Primary: {detail.project.primaryLanguage || 'N/A'}</span>
                        <span>·</span>
                        <span className="font-mono tabular-nums">{detail.project.fileCount} files</span>
                        <span>·</span>
                        <span className="font-mono tabular-nums">
                          {(detail.project.totalBytes / 1024).toFixed(1)} KB
                        </span>
                      </div>
                      {detail.project.importMethod === 'github' && detail.project.githubRepoUrl && (
                        <div className="pt-1.5 flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono">
                          <span className="text-cyan-300 truncate max-w-xs">
                            {detail.project.githubOwner}/{detail.project.githubRepo}
                          </span>
                          {detail.project.githubBranch && (
                            <span className="inline-flex items-center gap-1">
                              <GitBranch className="h-3 w-3 text-slate-500" />
                              {detail.project.githubBranch}
                            </span>
                          )}
                          {detail.project.githubCommitSha && (
                            <span className="inline-flex items-center gap-1">
                              <GitCommitHorizontal className="h-3 w-3 text-slate-500" />
                              {detail.project.githubCommitSha.slice(0, 7)}
                            </span>
                          )}
                          {detail.project.lastImportedAt && (
                            <span className="font-sans text-slate-500">
                              Imported {new Date(detail.project.lastImportedAt).toLocaleString()}
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => onNavigate('new-scan', { projectId: detail.project.id })}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 whitespace-nowrap"
                      >
                        <Play className="h-3.5 w-3.5" />
                        <span>Run Scan</span>
                      </button>
                      {detail.project.importMethod === 'github' && (
                        <button
                          type="button"
                          disabled={refreshingGitHub}
                          onClick={handleRefreshFromGitHub}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 px-3 py-2 text-xs font-medium text-cyan-200 hover:bg-cyan-500/10 disabled:opacity-50 whitespace-nowrap"
                        >
                          <RefreshCw className={`h-3.5 w-3.5 ${refreshingGitHub ? 'animate-spin' : ''}`} />
                          <span>{refreshingGitHub ? 'Refreshing...' : 'Refresh from GitHub'}</span>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          setEditingProject(detail.project);
                          setFormName(detail.project.name);
                          setFormDesc(detail.project.description);
                          setShowCreateForm(true);
                        }}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 whitespace-nowrap"
                      >
                        <Edit3 className="h-3.5 w-3.5" />
                        <span>Edit</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setDeleteTarget(detail.project)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-rose-900/60 px-3 py-2 text-xs font-medium text-rose-300 hover:bg-rose-950/40 whitespace-nowrap"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        <span>Delete</span>
                      </button>
                    </div>
                  </div>

                  {/* Upload Box */}
                  <div className="border-t border-slate-800 pt-5 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-medium text-slate-200">Upload Source Code or ZIP Archive</p>
                        <p className="text-xs text-slate-400">
                          Supports Python, JS/TS, Java, C/C++, and dependency manifests. Max 15 MB ZIP / 2 MB per file. Executable binaries and path traversal entries are blocked.
                        </p>
                      </div>
                      <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700 bg-[#131c31] px-4 py-2 text-xs font-medium text-slate-200 hover:border-cyan-500/50 whitespace-nowrap shrink-0">
                        <Upload className="h-3.5 w-3.5 text-cyan-400" />
                        <span>{uploading ? 'Uploading...' : 'Select ZIP or Files'}</span>
                        <input
                          type="file"
                          multiple
                          disabled={uploading}
                          onChange={handleFileUpload}
                          className="hidden"
                        />
                      </label>
                    </div>

                    {detail.unsupportedLanguages.length > 0 && (
                      <div className="rounded-lg border border-amber-800/60 bg-amber-950/30 px-3.5 py-2.5 flex items-start gap-2.5 text-xs text-amber-200">
                        <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                        <span>
                          Limited scanning support for detected language(s):{' '}
                          {detail.unsupportedLanguages.join(', ')}. Secret detection and manifest checks still run, while deep AST/SAST coverage targets Python, JavaScript, and TypeScript.
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Files Table */}
                <div className="rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden">
                  <div className="border-b border-slate-800 px-6 py-3.5 flex items-center justify-between">
                    <h3 className="font-display text-sm font-semibold text-slate-100">
                      Project Files ({detail.files.length})
                    </h3>
                    {detail.project.languages.length > 0 && (
                      <span className="text-xs text-slate-400">
                        Languages: {detail.project.languages.join(', ')}
                      </span>
                    )}
                  </div>

                  {detail.files.length === 0 ? (
                    <div className="p-6 text-center text-sm text-slate-500">
                      No files uploaded to this project yet.
                    </div>
                  ) : (
                    <div className="max-h-64 overflow-y-auto divide-y divide-slate-800/60">
                      {detail.files.map((file) => (
                        <button
                          key={file.id}
                          type="button"
                          onClick={() => handleViewFile(file.relativePath)}
                          className="w-full px-6 py-2.5 flex items-center justify-between gap-4 text-left hover:bg-slate-800/30 transition-colors"
                        >
                          <div className="flex items-center gap-2.5 min-w-0">
                            <FileCode2 className="h-4 w-4 text-slate-500 shrink-0" />
                            <span className="font-mono text-xs text-slate-200 truncate">
                              {file.relativePath}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-slate-400 shrink-0">
                            <span>{file.language}</span>
                            <span className="font-mono tabular-nums">{file.sizeBytes} B</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* File Source Preview */}
                {viewingFile && (
                  <div className="rounded-xl border border-slate-800 bg-[#060a14] overflow-hidden">
                    <div className="border-b border-slate-800 bg-[#0e1526] px-4 py-2.5 flex items-center justify-between">
                      <span className="font-mono text-xs text-cyan-300">{viewingFile.relativePath}</span>
                      <button
                        type="button"
                        onClick={() => setViewingFile(null)}
                        className="text-xs text-slate-400 hover:text-slate-200"
                      >
                        Close Preview
                      </button>
                    </div>
                    <pre className="p-4 max-h-80 overflow-auto font-mono text-xs text-slate-300 leading-5">
                      {viewingFile.content}
                    </pre>
                  </div>
                )}

                {/* Project Scan History */}
                <div className="rounded-xl border border-slate-800 bg-[#0e1526] overflow-hidden">
                  <div className="border-b border-slate-800 px-6 py-3.5">
                    <h3 className="font-display text-sm font-semibold text-slate-100">
                      Project Security History ({detail.scans.length})
                    </h3>
                  </div>
                  {detail.scans.length === 0 ? (
                    <div className="p-6 text-center text-sm text-slate-500">
                      No scans executed on this project yet.
                    </div>
                  ) : (
                    <div className="divide-y divide-slate-800/60">
                      {detail.scans.map((scan) => (
                        <div
                          key={scan.id}
                          className="px-6 py-3 flex items-center justify-between gap-4 text-xs"
                        >
                          <div className="space-y-0.5">
                            <p className="font-medium text-slate-200 capitalize">
                              {scan.triggerType} Scan · {scan.status}
                              {scan.commitSha && (
                                <span className="ml-2 font-mono text-[11px] text-cyan-300">
                                  {scan.repoBranch || 'branch'} @ {scan.commitSha.slice(0, 7)}
                                </span>
                              )}
                            </p>
                            <p className="font-mono text-slate-500 tabular-nums">
                              {new Date(scan.startedAt).toLocaleString()}
                            </p>
                          </div>
                          <div className="flex items-center gap-4 font-mono tabular-nums">
                            <span className="text-rose-400">C:{scan.criticalCount}</span>
                            <span className="text-orange-400">H:{scan.highCount}</span>
                            <span className="text-amber-400">M:{scan.mediumCount}</span>
                            <span className="text-sky-400">L:{scan.lowCount}</span>
                            <button
                              type="button"
                              onClick={() => onNavigate('findings', { projectId: detail.project.id, scanId: scan.id })}
                              className="text-cyan-400 hover:text-cyan-300 font-sans font-medium"
                            >
                              View Findings
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
