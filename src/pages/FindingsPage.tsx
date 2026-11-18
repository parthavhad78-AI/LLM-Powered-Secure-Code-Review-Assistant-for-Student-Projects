import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  Bot,
  Check,
  CheckCircle2,
  Download,
  RefreshCw,
  Search,
  ShieldAlert,
  Wrench,
  X,
} from 'lucide-react';
import type {
  AIAnalysis,
  Finding,
  Project,
  RemediationHistoryEntry,
  RemediationProposal,
  ScanDiagnostic,
  ScanSession,
  SourceContext,
} from '../../shared/types';
import { apiRequest } from '../api/client';
import { CodeDiffView } from '../components/CodeDiffView';
import {
  DetectionSourceLabel,
  RemediationStatusLabel,
  SeverityIndicator,
  ValidationStatusLabel,
} from '../components/SeverityBadge';
import { VulnerableCodeViewer } from '../components/VulnerableCodeViewer';
import type { NavSection } from '../layouts/AppShell';

const CATEGORY_TO_TOPIC_SLUG: Record<string, string> = {
  'SQL Injection': 'sql-injection',
  'Cross-Site Scripting': 'cross-site-scripting',
  'Broken Authentication': 'broken-authentication',
  'Broken Authorization': 'broken-authentication',
  'Hardcoded Credentials': 'hardcoded-credentials',
  'Exposed Secrets': 'hardcoded-credentials',
  'Plaintext Password Storage': 'weak-cryptography',
  'Insecure Deserialization': 'insecure-deserialization',
  'Path Traversal': 'path-traversal',
  'Command Injection': 'command-injection',
  'Code Injection': 'command-injection',
  'Weak Cryptography': 'weak-cryptography',
  'Insecure Transport': 'weak-cryptography',
  'Vulnerable Dependency': 'insecure-dependencies',
  'Security Misconfiguration': 'security-misconfiguration',
  'Error Handling': 'security-misconfiguration',
  'Open Redirect': 'security-misconfiguration',
};

function isInvalidAuthPlaceholder(val: string | null | undefined): boolean {
  if (!val) return false;
  return /^(requires\s+login|login\s+required|authentication\s+required|please\s+log\s*in|unauthorized)\.?$/i.test(
    val.trim()
  );
}

export function FindingsPage({
  initialProjectId,
  initialScanId,
  onNavigate,
}: {
  initialProjectId?: string;
  initialScanId?: string;
  onNavigate: (section: NavSection, context?: { topicSlug?: string; projectId?: string }) => void;
}) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanDiagnostics, setScanDiagnostics] = useState<ScanDiagnostic[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [projectIdFilter, setProjectIdFilter] = useState(initialProjectId || 'all');
  const [scanIdFilter, setScanIdFilter] = useState(initialScanId || 'latest');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [scannerFilter, setScannerFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'severity' | 'file' | 'line'>('severity');

  // Detail inspection state
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailData, setDetailData] = useState<{
    finding: Finding;
    sourceContext: SourceContext;
    diagnostics: ScanDiagnostic[];
    analyses: AIAnalysis[];
    remediations: RemediationProposal[];
    history: RemediationHistoryEntry[];
  } | null>(null);

  // Action loading states
  const [analyzingAi, setAnalyzingAi] = useState(false);
  const [generatingFix, setGeneratingFix] = useState(false);
  const [applyingRemId, setApplyingRemId] = useState<string | null>(null);
  const [validatingRemId, setValidatingRemId] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);

  useEffect(() => {
    setProjectIdFilter(initialProjectId || 'all');
    setScanIdFilter(initialScanId || 'latest');
  }, [initialProjectId, initialScanId]);

  async function loadList() {
    setLoading(true);
    setError(null);
    try {
      const qs = new URLSearchParams();
      if (projectIdFilter !== 'all') qs.set('projectId', projectIdFilter);
      if (scanIdFilter !== 'latest' && scanIdFilter !== 'all') {
        qs.set('scanId', scanIdFilter);
      } else if (scanIdFilter === 'all') {
        qs.set('scope', 'all');
      }

      const [projRes, scansRes, findingsRes] = await Promise.all([
        apiRequest<{ projects: Project[] }>('/api/projects'),
        apiRequest<{ scans: ScanSession[] }>('/api/scans'),
        scanIdFilter !== 'latest' && scanIdFilter !== 'all'
          ? apiRequest<{ findings: Finding[]; diagnostics?: ScanDiagnostic[] }>(
              `/api/scans/${scanIdFilter}/findings`
            )
          : apiRequest<{ findings: Finding[]; diagnostics?: ScanDiagnostic[] }>(
              `/api/findings${qs.toString() ? `?${qs.toString()}` : ''}`
            ),
      ]);
      setProjects(projRes.projects);
      setScans(scansRes.scans);

      // Reconcile state cleanly by canonical finding ID so refreshes never append duplicates
      const dedupedById = Array.from(
        new Map(findingsRes.findings.map((item) => [item.id, item])).values()
      );
      setFindings(dedupedById);
      setScanDiagnostics(
        Array.isArray(findingsRes.diagnostics) ? findingsRes.diagnostics : []
      );

      if (dedupedById.length === 0) {
        setSelectedFindingId(null);
        setDetailData(null);
      } else if (!selectedFindingId || !dedupedById.some((f) => f.id === selectedFindingId)) {
        loadDetail(dedupedById[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security findings.');
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(findingId: string) {
    setSelectedFindingId(findingId);
    setDetailLoading(true);
    setActionErr(null);
    setActionMsg(null);
    try {
      const res = await apiRequest<{
        finding: Finding;
        sourceContext: SourceContext;
        diagnostics: ScanDiagnostic[];
        analyses: AIAnalysis[];
        remediations: RemediationProposal[];
        history: RemediationHistoryEntry[];
      }>(`/api/findings/${findingId}`);
      setDetailData(res);
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Failed to load finding details.');
    } finally {
      setDetailLoading(false);
    }
  }

  useEffect(() => {
    loadList();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectIdFilter, scanIdFilter]);

  const categories = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))).sort(),
    [findings]
  );

  const filteredFindings = useMemo(() => {
    const SEV_ORDER: Record<string, number> = {
      Critical: 1,
      High: 2,
      Medium: 3,
      Low: 4,
      Informational: 5,
    };

    const list = findings.filter((f) => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (scannerFilter !== 'all') {
        const scanners = f.contributingScanners?.length ? f.contributingScanners : [f.scannerName];
        if (!scanners.includes(scannerFilter)) return false;
      }
      if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
      if (statusFilter !== 'all' && f.remediationStatus !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const hay = `${f.title} ${f.filePath} ${f.ruleId} ${f.description} ${f.cweId || ''} ${(f.contributingScanners || []).join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    return [...list].sort((a, b) => {
      if (sortBy === 'file') {
        if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
        return a.startLine - b.startLine;
      }
      if (sortBy === 'line') {
        if (a.startLine !== b.startLine) return a.startLine - b.startLine;
        return a.filePath.localeCompare(b.filePath);
      }
      const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
      if (sd !== 0) return sd;
      if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
      return a.startLine - b.startLine;
    });
  }, [findings, severityFilter, scannerFilter, categoryFilter, statusFilter, searchQuery, sortBy]);

  const availableScansForProject = useMemo(() => {
    if (projectIdFilter === 'all') return scans;
    return scans.filter((s) => s.projectId === projectIdFilter);
  }, [scans, projectIdFilter]);

  const summaryCounts = useMemo(
    () => ({
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'Critical').length,
      high: findings.filter((f) => f.severity === 'High').length,
      medium: findings.filter((f) => f.severity === 'Medium').length,
      low: findings.filter((f) => f.severity === 'Low').length,
      info: findings.filter((f) => f.severity === 'Informational').length,
    }),
    [findings]
  );

  async function handleAnalyzeWithGemini() {
    if (!detailData) return;
    setAnalyzingAi(true);
    setActionErr(null);
    setActionMsg(null);
    try {
      await apiRequest<{ analysis: AIAnalysis }>('/api/ai/analyze', {
        method: 'POST',
        body: JSON.stringify({ findingId: detailData.finding.id }),
      });
      setActionMsg('Gemini AI vulnerability explanation and false-positive assessment generated.');
      await loadDetail(detailData.finding.id);
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Gemini AI analysis failed.');
    } finally {
      setAnalyzingAi(false);
    }
  }

  async function handleGenerateFix() {
    if (!detailData) return;
    setGeneratingFix(true);
    setActionErr(null);
    setActionMsg(null);
    try {
      await apiRequest<{ remediation: RemediationProposal }>(
        `/api/findings/${detailData.finding.id}/fix`,
        { method: 'POST' }
      );
      setActionMsg('Proposed code fix generated. Review the diff below before approving.');
      await loadDetail(detailData.finding.id);
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Failed to generate AI fix.');
    } finally {
      setGeneratingFix(false);
    }
  }

  async function handleApproveFix(remediationId: string) {
    if (!detailData) return;
    setApplyingRemId(remediationId);
    setActionErr(null);
    setActionMsg(null);
    try {
      await apiRequest(`/api/remediations/${remediationId}/approve`, { method: 'POST' });
      setActionMsg(
        'Fix approved and applied safely with an automatic backup snapshot. Run validation to verify.'
      );
      await loadDetail(detailData.finding.id);
      await loadList();
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Failed to apply fix.');
    } finally {
      setApplyingRemId(null);
    }
  }

  async function handleRejectFix(remediationId: string) {
    if (!detailData) return;
    setApplyingRemId(remediationId);
    setActionErr(null);
    try {
      await apiRequest(`/api/remediations/${remediationId}/reject`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'Rejected after student review' }),
      });
      setActionMsg('Proposed fix rejected. Original source code remains untouched.');
      await loadDetail(detailData.finding.id);
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Failed to reject fix.');
    } finally {
      setApplyingRemId(null);
    }
  }

  async function handleValidateFix(remediationId: string) {
    if (!detailData) return;
    setValidatingRemId(remediationId);
    setActionErr(null);
    setActionMsg(null);
    try {
      const res = await apiRequest<{ proposal: RemediationProposal }>(
        `/api/remediations/${remediationId}/validate`,
        { method: 'POST' }
      );
      setActionMsg(`Static rescan completed: ${res.proposal.validationSummary}`);
      await loadDetail(detailData.finding.id);
      await loadList();
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Fix validation failed.');
    } finally {
      setValidatingRemId(null);
    }
  }

  async function handleUpdateStatus(nextStatus: string) {
    if (!detailData) return;
    try {
      await apiRequest(`/api/findings/${detailData.finding.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      await loadDetail(detailData.finding.id);
      await loadList();
    } catch (err) {
      setActionErr(err instanceof Error ? err.message : 'Failed to update finding status.');
    }
  }

  const latestAnalysis = detailData?.analyses[0] || null;
  const topicSlug = detailData
    ? CATEGORY_TO_TOPIC_SLUG[detailData.finding.category] || 'security-misconfiguration'
    : 'security-misconfiguration';

  const activeDiagnostics = useMemo(() => {
    const list = detailData?.diagnostics?.length ? detailData.diagnostics : scanDiagnostics;
    if (!detailData) return list;
    return list.filter((d) => d.filePath === detailData.finding.filePath);
  }, [detailData, scanDiagnostics]);

  const contributingScanners = useMemo(() => {
    if (!detailData) return [];
    const list = detailData.finding.contributingScanners;
    return list && list.length > 0 ? list : [detailData.finding.scannerName];
  }, [detailData]);

  const scannerEvidenceEntries = useMemo(() => {
    if (!detailData) return [];
    if (detailData.finding.scannerEvidence && detailData.finding.scannerEvidence.length > 0) {
      return detailData.finding.scannerEvidence;
    }
    return [
      {
        scannerName: detailData.finding.scannerName,
        ruleId: detailData.finding.ruleId,
        detectionSource: detailData.finding.detectionSource,
        title: detailData.finding.title,
        description: detailData.finding.description,
        severity: detailData.finding.severity,
        confidence: detailData.finding.confidence,
        startLine: detailData.finding.startLine,
        endLine: detailData.finding.endLine,
        startCol: detailData.finding.startCol ?? null,
        endCol: detailData.finding.endCol ?? null,
        redactedEvidence: detailData.finding.redactedEvidence,
      },
    ];
  }, [detailData]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100 tracking-tight">
            Security Findings
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Inspect scanned source snapshots, multi-scanner evidence, Gemini AI security explanations, and remediations.
          </p>
        </div>
      </div>

      {/* Unique Findings Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-slate-400">Unique Findings</p>
          <p className="font-mono text-lg font-semibold text-slate-100 tabular-nums">{summaryCounts.total}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-rose-400">Critical</p>
          <p className="font-mono text-lg font-semibold text-rose-300 tabular-nums">{summaryCounts.critical}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-orange-400">High</p>
          <p className="font-mono text-lg font-semibold text-orange-300 tabular-nums">{summaryCounts.high}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-amber-400">Medium</p>
          <p className="font-mono text-lg font-semibold text-amber-300 tabular-nums">{summaryCounts.medium}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-sky-400">Low</p>
          <p className="font-mono text-lg font-semibold text-sky-300 tabular-nums">{summaryCounts.low}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-slate-400">Informational</p>
          <p className="font-mono text-lg font-semibold text-slate-300 tabular-nums">{summaryCounts.info}</p>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#0e1526] px-3.5 py-2.5">
          <p className="text-[11px] text-amber-300">Diagnostics</p>
          <p className="font-mono text-lg font-semibold text-amber-200 tabular-nums">{scanDiagnostics.length}</p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-8 gap-3">
        <div className="lg:col-span-2 relative">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rule, file path, CWE, title..."
            className="w-full rounded-lg border border-slate-800 bg-[#080d1a] py-2 pl-9 pr-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <select
          aria-label="Filter by project"
          value={projectIdFilter}
          onChange={(e) => {
            setProjectIdFilter(e.target.value);
            setScanIdFilter('latest');
          }}
          className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>

        <select
          aria-label="Select scan version"
          value={scanIdFilter}
          onChange={(e) => setScanIdFilter(e.target.value)}
          className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
        >
          <option value="latest">Latest Scan (Default)</option>
          {availableScansForProject.map((s) => (
            <option key={s.id} value={s.id}>
              {new Date(s.startedAt).toLocaleString()} ({s.totalFindings})
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by severity"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>

        <select
          aria-label="Filter by scanner"
          value={scannerFilter}
          onChange={(e) => setScannerFilter(e.target.value)}
          className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Scanners</option>
          <option value="custom">Custom AST/Rules</option>
          <option value="bandit">Bandit</option>
          <option value="semgrep">Semgrep</option>
          <option value="gitleaks">Gitleaks</option>
          <option value="eslint">ESLint Security</option>
          <option value="osv">OSV-Scanner</option>
        </select>

        <select
          aria-label="Filter by remediation status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_review">In Review</option>
          <option value="approved">Applied</option>
          <option value="remediated">Remediated</option>
          <option value="false_positive">False Positive</option>
        </select>

        <select
          aria-label="Sort findings"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as 'severity' | 'file' | 'line')}
          className="rounded-lg border border-slate-800 bg-[#080d1a] px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
        >
          <option value="severity">Sort: Severity</option>
          <option value="file">Sort: File Path</option>
          <option value="line">Sort: Line Number</option>
        </select>
      </div>

      {categories.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500">Category:</span>
          <button
            type="button"
            onClick={() => setCategoryFilter('all')}
            className={`rounded-md px-2.5 py-1 transition-colors ${
              categoryFilter === 'all'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            All ({findings.length})
          </button>
          {categories.map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setCategoryFilter(cat)}
              className={`rounded-md px-2.5 py-1 transition-colors ${
                categoryFilter === cat
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading ? (
        <div className="h-72 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
      ) : filteredFindings.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-12 text-center space-y-2">
          <p className="text-base font-medium text-slate-200">No matching findings</p>
          <p className="text-sm text-slate-400">
            Run a security scan on an uploaded project or broaden your search filters.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
          {/* Findings List */}
          <div className="xl:col-span-5 rounded-xl border border-slate-800 bg-[#0e1526] divide-y divide-slate-800/80 max-h-[820px] overflow-y-auto">
            {filteredFindings.map((f) => {
              const active = f.id === selectedFindingId;
              const scannerLabel =
                f.contributingScanners && f.contributingScanners.length > 1
                  ? f.contributingScanners.map((s) => s.toUpperCase()).join(' + ')
                  : f.scannerName.toUpperCase();
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => loadDetail(f.id)}
                  className={`w-full text-left p-4 space-y-2 transition-colors ${
                    active ? 'bg-cyan-500/8' : 'hover:bg-slate-800/30'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <SeverityIndicator severity={f.severity} />
                    <RemediationStatusLabel status={f.remediationStatus} />
                  </div>
                  <p
                    className={`text-sm font-medium leading-snug ${
                      active ? 'text-cyan-200' : 'text-slate-100'
                    }`}
                  >
                    {f.title}
                  </p>
                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    <span className="font-mono text-slate-300 tabular-nums">
                      {f.filePath}:{f.startLine}
                      {f.endLine > f.startLine ? `-${f.endLine}` : ''}
                    </span>
                    <span>·</span>
                    <span>{scannerLabel}</span>
                    <span>·</span>
                    <DetectionSourceLabel source={f.detectionSource} />
                  </div>
                </button>
              );
            })}
          </div>

          {/* Finding Inspector & Remediation Workspace */}
          <div className="xl:col-span-7 space-y-5">
            {detailLoading ? (
              <div className="h-96 rounded-xl border border-slate-800 bg-[#0e1526] animate-pulse" />
            ) : detailData ? (
              <>
                {/* Code Analysis Diagnostics Banner (Separated from Vulnerabilities) */}
                {activeDiagnostics.length > 0 && (
                  <div className="rounded-xl border border-amber-800/60 bg-amber-950/20 px-4 py-3.5 space-y-2">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-200">
                        Code Analysis Diagnostics ({activeDiagnostics.length})
                      </h3>
                    </div>
                    <div className="space-y-2">
                      {activeDiagnostics.map((diag) => {
                        const scannersList =
                          diag.contributingScanners && diag.contributingScanners.length > 0
                            ? diag.contributingScanners
                            : [diag.scannerName];
                        return (
                          <div key={diag.id} className="text-xs text-slate-300 space-y-1">
                            <div className="flex flex-wrap items-baseline gap-2">
                              <span className="font-mono text-amber-300 tabular-nums">
                                {diag.filePath}:{diag.line}
                                {diag.column ? `:${diag.column}` : ''}
                              </span>
                              <span className="text-slate-600">·</span>
                              <span className="uppercase text-slate-400 font-medium">
                                {scannersList.join(' + ')}
                              </span>
                              <span className="text-slate-600">·</span>
                              <span>{diag.message}</span>
                            </div>
                            {diag.scannerMessages && diag.scannerMessages.length > 1 && (
                              <div className="pl-3 border-l border-amber-800/50 space-y-0.5 text-[11px] text-slate-400">
                                {diag.scannerMessages.map((sm, idx) => (
                                  <p key={`${diag.id}-${sm.scannerName}-${idx}`}>
                                    <span className="uppercase font-semibold text-slate-300">
                                      {sm.scannerName}:
                                    </span>{' '}
                                    {sm.message}
                                  </p>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-6">
                  {/* Section A — Finding Header */}
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <SeverityIndicator severity={detailData.finding.severity} />
                        <RemediationStatusLabel status={detailData.finding.remediationStatus} />
                        <span className="text-slate-600">·</span>
                        <DetectionSourceLabel source={detailData.finding.detectionSource} />
                        <span className="text-slate-600">·</span>
                        <span className="text-slate-300 font-medium">
                          {contributingScanners.map((s) => s.toUpperCase()).join(' + ')}
                        </span>
                      </div>
                      <h2 className="font-display text-lg font-semibold text-slate-100 leading-snug">
                        {detailData.finding.title}
                      </h2>
                      <p className="text-xs text-slate-400 font-mono tabular-nums">
                        {detailData.finding.filePath}:{detailData.finding.startLine}
                        {detailData.finding.endLine > detailData.finding.startLine
                          ? `-${detailData.finding.endLine}`
                          : ''}
                        {' · '}
                        {detailData.finding.cweId || 'CWE N/A'} ·{' '}
                        {detailData.finding.owaspCategory || 'OWASP N/A'} ·{' '}
                        {detailData.finding.ruleId}
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <select
                        aria-label="Update finding status"
                        value={detailData.finding.remediationStatus}
                        onChange={(e) => handleUpdateStatus(e.target.value)}
                        className="rounded-lg border border-slate-700 bg-[#080d1a] px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
                      >
                        <option value="open">Open</option>
                        <option value="in_review">In Review</option>
                        <option value="approved">Applied</option>
                        <option value="remediated">Remediated</option>
                        <option value="accepted_risk">Accepted Risk</option>
                        <option value="false_positive">False Positive</option>
                      </select>
                      <button
                        type="button"
                        onClick={() => onNavigate('learning', { topicSlug })}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-cyan-500/50 whitespace-nowrap"
                      >
                        <BookOpen className="h-3.5 w-3.5 text-cyan-400" />
                        <span>Learn Topic</span>
                      </button>
                    </div>
                  </div>

                  {actionErr && (
                    <div className="rounded-lg border border-rose-800/70 bg-rose-950/40 px-3.5 py-2.5 text-xs text-rose-200">
                      {actionErr}
                    </div>
                  )}
                  {actionMsg && (
                    <div className="rounded-lg border border-emerald-800/70 bg-emerald-950/35 px-3.5 py-2.5 text-xs text-emerald-200">
                      {actionMsg}
                    </div>
                  )}

                  {/* Section B — Vulnerable Source Code */}
                  <section className="space-y-2.5 border-t border-slate-800 pt-5">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Vulnerable Source Code
                    </h3>
                    <VulnerableCodeViewer
                      sourceContext={detailData.sourceContext}
                      findingId={detailData.finding.id}
                      filePath={detailData.finding.filePath}
                    />
                  </section>

                  {/* Sections C, D, E — Educational & Security Guidance */}
                  <div className="grid grid-cols-1 gap-4 border-t border-slate-800 pt-5">
                    <section className="space-y-1">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                        Why This Is Vulnerable
                      </h3>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {detailData.finding.guidance?.whyVulnerable ||
                          detailData.finding.description}
                      </p>
                    </section>

                    <section className="space-y-1">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                        Potential Security Impact
                      </h3>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {detailData.finding.guidance?.potentialImpact ||
                          'Depending on reachability and deployment context, this weakness may compromise data confidentiality or integrity.'}
                      </p>
                    </section>

                    <section className="space-y-1">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                        Recommended Secure Approach
                      </h3>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {detailData.finding.guidance?.recommendedApproach ||
                          detailData.finding.recommendation}
                      </p>
                    </section>
                  </div>

                  {/* Section F — Scanner Evidence (Strictly Separated from Source Code & AI) */}
                  <section className="space-y-3 border-t border-slate-800 pt-5">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                        Scanner Evidence
                      </h3>
                      <span className="text-xs text-slate-500 font-mono tabular-nums">
                        {scannerEvidenceEntries.length} detection{scannerEvidenceEntries.length === 1 ? '' : 's'}
                      </span>
                    </div>

                    {scannerEvidenceEntries.length === 0 ? (
                      <p className="text-xs text-slate-400">Scanner evidence unavailable.</p>
                    ) : (
                      <div className="space-y-2.5">
                        {scannerEvidenceEntries.map((ev, idx) => {
                          const hasSafeSecretEvidence =
                            ev.redactedEvidence && !isInvalidAuthPlaceholder(ev.redactedEvidence);
                          return (
                            <div
                              key={`${ev.scannerName}-${ev.ruleId}-${idx}`}
                              className="rounded-lg border border-slate-800 bg-[#080d1a] p-3.5 space-y-1.5"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                                <div className="flex flex-wrap items-center gap-2">
                                  <ShieldAlert className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                                  <span className="font-semibold uppercase text-slate-200">
                                    {ev.scannerName}
                                  </span>
                                  <span className="text-slate-600">·</span>
                                  <span className="font-mono text-slate-400">{ev.ruleId}</span>
                                  <span className="text-slate-600">·</span>
                                  <DetectionSourceLabel source={ev.detectionSource} />
                                </div>
                                <span className="font-mono text-slate-400 tabular-nums">
                                  Lines {ev.startLine}
                                  {ev.endLine > ev.startLine ? `-${ev.endLine}` : ''} · Confidence:{' '}
                                  {ev.confidence}
                                </span>
                              </div>
                              <p className="text-xs text-slate-300 leading-relaxed">
                                {ev.description}
                              </p>
                              {hasSafeSecretEvidence && (
                                <p className="font-mono text-xs text-amber-300 pt-1">
                                  Redacted Secret Evidence: {ev.redactedEvidence}
                                </p>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </section>

                  {/* AI & Remediation Action Bar */}
                  <div className="flex flex-wrap items-center gap-3 border-t border-slate-800 pt-5">
                    <button
                      type="button"
                      disabled={analyzingAi}
                      onClick={handleAnalyzeWithGemini}
                      className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/12 px-4 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50 whitespace-nowrap"
                    >
                      <Bot className="h-3.5 w-3.5" />
                      <span>{analyzingAi ? 'Analyzing with Gemini...' : 'Explain with Gemini AI'}</span>
                    </button>
                    <button
                      type="button"
                      disabled={generatingFix}
                      onClick={handleGenerateFix}
                      className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 whitespace-nowrap"
                    >
                      <Wrench className="h-3.5 w-3.5" />
                      <span>{generatingFix ? 'Generating Secure Fix...' : 'Generate AI Code Fix'}</span>
                    </button>
                  </div>
                </div>

                {/* Section G — AI Security Analysis (Advisory) */}
                {latestAnalysis && (
                  <div className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                      <div>
                        <h3 className="font-display text-base font-semibold text-slate-100">
                          AI Security Analysis (Advisory)
                        </h3>
                        <p className="text-xs text-slate-400 font-mono">
                          Model: {latestAnalysis.modelName} · Assessment:{' '}
                          <span className="text-cyan-300">
                            {latestAnalysis.falsePositiveAssessment.replace(/_/g, ' ')}
                          </span>
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div className="space-y-1">
                        <p className="text-xs font-semibold text-slate-300">What It Means</p>
                        <p className="text-slate-300 leading-relaxed">
                          {latestAnalysis.vulnerabilityMeaning}
                        </p>
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs font-semibold text-slate-300">Why It Is Unsafe</p>
                        <p className="text-slate-300 leading-relaxed">{latestAnalysis.whyUnsafe}</p>
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs font-semibold text-slate-300">How It Could Be Exploited</p>
                        <p className="text-slate-300 leading-relaxed">
                          {latestAnalysis.exploitationScenario}
                        </p>
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs font-semibold text-slate-300">Real-World Impact &amp; Risk</p>
                        <p className="text-slate-300 leading-relaxed">
                          {latestAnalysis.realWorldImpact} {latestAnalysis.riskContext}
                        </p>
                      </div>
                    </div>

                    <div className="space-y-1.5 border-t border-slate-800 pt-3 text-sm">
                      <p className="text-xs font-semibold text-slate-300">
                        False-Positive &amp; Uncertainty Context
                      </p>
                      <p className="text-slate-300">{latestAnalysis.falsePositiveReasoning}</p>
                      <p className="text-xs text-amber-300">{latestAnalysis.uncertaintyNote}</p>
                    </div>

                    <div className="space-y-1.5 border-t border-slate-800 pt-3">
                      <p className="text-xs font-semibold text-slate-300">
                        Recommended Secure Pattern ({latestAnalysis.cweOwaspContext})
                      </p>
                      <p className="text-sm text-slate-300">{latestAnalysis.secureRecommendation}</p>
                      <pre className="mt-2 rounded-lg border border-slate-800 bg-[#060a14] p-3 font-mono text-xs text-emerald-200 overflow-x-auto">
                        {latestAnalysis.correctedCodeExample}
                      </pre>
                    </div>
                  </div>
                )}

                {/* Section H — AI Code Remediation & Validation */}
                {detailData.remediations.map((rem) => (
                  <div
                    key={rem.id}
                    className="rounded-xl border border-slate-800 bg-[#0e1526] p-6 space-y-4"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <h3 className="font-display text-base font-semibold text-slate-100">
                          AI Code Remediation
                        </h3>
                        <p className="text-xs text-slate-400">
                          Proposal status:{' '}
                          <span className="capitalize text-slate-200">{rem.status}</span>
                          {rem.backupPath && ` · Backup saved: ${rem.backupPath}`}
                        </p>
                      </div>
                      <ValidationStatusLabel status={rem.validationStatus} />
                    </div>

                    <p className="text-sm text-slate-300">{rem.explanation}</p>
                    <p className="text-xs text-slate-400">Summary: {rem.diffSummary}</p>

                    <CodeDiffView
                      originalCode={rem.originalCode}
                      proposedCode={rem.proposedCode}
                      filePath={rem.filePath}
                    />

                    {rem.validationSummary && (
                      <div className="rounded-lg border border-slate-800 bg-[#080d1a] px-4 py-3 text-xs text-slate-200 flex items-start gap-2">
                        <CheckCircle2 className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                        <span>{rem.validationSummary}</span>
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-3 pt-1">
                      {rem.status === 'pending' && (
                        <>
                          <button
                            type="button"
                            disabled={applyingRemId === rem.id}
                            onClick={() => handleApproveFix(rem.id)}
                            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50 whitespace-nowrap"
                          >
                            <Check className="h-3.5 w-3.5" />
                            <span>
                              {applyingRemId === rem.id ? 'Applying...' : 'Approve & Apply Fix'}
                            </span>
                          </button>
                          <button
                            type="button"
                            disabled={applyingRemId === rem.id}
                            onClick={() => handleRejectFix(rem.id)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-rose-800/70 px-3.5 py-2 text-xs font-medium text-rose-300 hover:bg-rose-950/40 whitespace-nowrap"
                          >
                            <X className="h-3.5 w-3.5" />
                            <span>Reject Proposal</span>
                          </button>
                        </>
                      )}

                      {(rem.status === 'applied' || rem.status === 'approved') && (
                        <button
                          type="button"
                          disabled={validatingRemId === rem.id}
                          onClick={() => handleValidateFix(rem.id)}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 whitespace-nowrap"
                        >
                          <RefreshCw
                            className={`h-3.5 w-3.5 ${
                              validatingRemId === rem.id ? 'animate-spin' : ''
                            }`}
                          />
                          <span>
                            {validatingRemId === rem.id
                              ? 'Validating...'
                              : 'Rescan & Validate Fix'}
                          </span>
                        </button>
                      )}

                      <a
                        href={`/api/remediations/${rem.id}/download`}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 whitespace-nowrap"
                      >
                        <Download className="h-3.5 w-3.5" />
                        <span>Download Patched File</span>
                      </a>
                    </div>
                  </div>
                ))}
              </>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
