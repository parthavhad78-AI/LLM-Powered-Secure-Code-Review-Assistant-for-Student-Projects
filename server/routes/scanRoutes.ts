import { Router } from 'express';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';
import {
  cancelScanExecution,
  executeProjectScan,
  getAllScannerHealth,
} from '../scanners/scannerManager.ts';
import { buildFindingGuidance } from '../scanners/findingGuidance.ts';
import { getProjectSourceDir } from '../scanners/security/fileSecurity.ts';
import { isAuthPlaceholderText, sanitizeScannerSnippet } from '../scanners/security/secretRedactor.ts';

export const scannerRoutes = Router();
scannerRoutes.use(requireAuth);

scannerRoutes.get('/', async (_req, res) => {
  const health = await getAllScannerHealth();
  res.json({ scanners: health });
});

scannerRoutes.get('/health', async (_req, res) => {
  const health = await getAllScannerHealth();
  res.json({
    scanners: health,
    availableCount: health.filter((s) => s.available).length,
    totalCount: health.length,
  });
});

export const scanRoutes = Router();
scanRoutes.use(requireAuth, requireCsrf);

export function mapDiagnosticRow(d: Record<string, unknown>) {
  const scannerName = String(d.scanner_name);
  let contributingScanners: string[] = [];
  try {
    const parsed = JSON.parse(String(d.contributing_scanners_json || '[]'));
    if (Array.isArray(parsed) && parsed.length > 0) {
      contributingScanners = parsed.map(String);
    }
  } catch {
    contributingScanners = [];
  }
  if (contributingScanners.length === 0) {
    contributingScanners = [scannerName];
  }

  let scannerMessages: Array<{
    scannerName: string;
    message: string;
    line: number;
    column: number | null;
  }> = [];
  try {
    const parsedMsgs = JSON.parse(String(d.scanner_messages_json || '[]'));
    if (Array.isArray(parsedMsgs) && parsedMsgs.length > 0) {
      scannerMessages = parsedMsgs;
    }
  } catch {
    scannerMessages = [];
  }
  if (scannerMessages.length === 0) {
    scannerMessages = [
      {
        scannerName,
        message: String(d.message),
        line: Number(d.line),
        column: d.column_num != null ? Number(d.column_num) : null,
      },
    ];
  }

  return {
    id: String(d.id),
    scanId: String(d.scan_id),
    projectId: String(d.project_id),
    canonicalKey: d.canonical_key ? String(d.canonical_key) : undefined,
    scannerName,
    contributingScanners,
    scannerMessages,
    filePath: String(d.file_path),
    line: Number(d.line),
    column: d.column_num != null ? Number(d.column_num) : null,
    severity: d.severity === 'warning' ? 'warning' : 'error',
    kind: d.kind === 'parse_warning' ? 'parse_warning' : 'syntax_error',
    message: String(d.message),
    createdAt: String(d.created_at),
  };
}

scanRoutes.post('/', async (req: AuthenticatedRequest, res) => {
  const { projectId, scanners } = req.body || {};
  if (!projectId || typeof projectId !== 'string') {
    res.status(400).json({ error: 'projectId is required.' });
    return;
  }

  const db = getDb();
  const project = db
    .prepare('SELECT id, name, file_count, source_path FROM projects WHERE id = ? AND user_id = ?')
    .get(projectId, req.auth!.userId) as
    | { id: string; name: string; file_count: number; source_path: string }
    | undefined;

  if (!project) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  if (project.file_count === 0) {
    res.status(400).json({ error: 'Upload source files or a ZIP archive before starting a security scan.' });
    return;
  }

  try {
    const sourceDir = getProjectSourceDir(req.auth!.userId, project.id);
    const scanSession = await executeProjectScan({
      userId: req.auth!.userId,
      projectId: project.id,
      sourcePath: sourceDir,
      scanners: Array.isArray(scanners) ? scanners.map(String) : undefined,
      triggerType: 'manual',
    });

    res.status(201).json({
      scan: {
        ...scanSession,
        projectName: project.name,
      },
    });
  } catch (err) {
    res.status(500).json({
      error: err instanceof Error ? err.message : 'Security scan execution failed.',
    });
  }
});

scanRoutes.get('/', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT s.*, p.name AS project_name
       FROM scan_sessions s
       JOIN projects p ON p.id = s.project_id
       WHERE s.user_id = ?
       ORDER BY s.started_at DESC
       LIMIT 50`
    )
    .all(req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({
    scans: rows.map((s) => ({
      id: String(s.id),
      projectId: String(s.project_id),
      projectName: String(s.project_name),
      userId: String(s.user_id),
      status: s.status,
      triggerType: s.trigger_type,
      scannersRequested: JSON.parse(String(s.scanners_requested_json || '[]')),
      totalFindings: Number(s.total_findings),
      criticalCount: Number(s.critical_count),
      highCount: Number(s.high_count),
      mediumCount: Number(s.medium_count),
      lowCount: Number(s.low_count),
      infoCount: Number(s.info_count),
      startedAt: String(s.started_at),
      completedAt: s.completed_at ? String(s.completed_at) : null,
      errorMessage: s.error_message ? String(s.error_message) : null,
      repoUrl: s.repo_url ? String(s.repo_url) : null,
      repoBranch: s.repo_branch ? String(s.repo_branch) : null,
      commitSha: s.commit_sha ? String(s.commit_sha) : null,
    })),
  });
});

scanRoutes.get('/:id', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const s = db
    .prepare(
      `SELECT s.*, p.name AS project_name
       FROM scan_sessions s
       JOIN projects p ON p.id = s.project_id
       WHERE s.id = ? AND s.user_id = ?`
    )
    .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

  if (!s) {
    res.status(404).json({ error: 'Scan session not found.' });
    return;
  }

  const scannerResults = db
    .prepare('SELECT * FROM scanner_results WHERE scan_id = ? ORDER BY scanner_name ASC')
    .all(req.params.id) as Array<Record<string, unknown>>;

  const diagnostics = db
    .prepare('SELECT * FROM scan_diagnostics WHERE scan_id = ? AND user_id = ? ORDER BY file_path ASC, line ASC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({
    scan: {
      id: String(s.id),
      projectId: String(s.project_id),
      projectName: String(s.project_name),
      userId: String(s.user_id),
      status: s.status,
      triggerType: s.trigger_type,
      scannersRequested: JSON.parse(String(s.scanners_requested_json || '[]')),
      totalFindings: Number(s.total_findings),
      criticalCount: Number(s.critical_count),
      highCount: Number(s.high_count),
      mediumCount: Number(s.medium_count),
      lowCount: Number(s.low_count),
      infoCount: Number(s.info_count),
      startedAt: String(s.started_at),
      completedAt: s.completed_at ? String(s.completed_at) : null,
      errorMessage: s.error_message ? String(s.error_message) : null,
      repoUrl: s.repo_url ? String(s.repo_url) : null,
      repoBranch: s.repo_branch ? String(s.repo_branch) : null,
      commitSha: s.commit_sha ? String(s.commit_sha) : null,
      scannerResults: scannerResults.map((sr) => ({
        id: String(sr.id),
        scanId: String(sr.scan_id),
        scannerName: String(sr.scanner_name),
        available: Boolean(sr.available),
        version: sr.version ? String(sr.version) : null,
        status: sr.status,
        durationMs: Number(sr.duration_ms),
        findingsCount: Number(sr.findings_count),
        errorMessage: sr.error_message ? String(sr.error_message) : null,
        installHint: sr.install_hint ? String(sr.install_hint) : null,
        executedAt: String(sr.executed_at),
      })),
      diagnostics: diagnostics.map(mapDiagnosticRow),
    },
  });
});

scanRoutes.get('/:id/diagnostics', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scan = db
    .prepare('SELECT id FROM scan_sessions WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!scan) {
    res.status(404).json({ error: 'Scan session not found.' });
    return;
  }

  const diagnostics = db
    .prepare('SELECT * FROM scan_diagnostics WHERE scan_id = ? AND user_id = ? ORDER BY file_path ASC, line ASC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({ diagnostics: diagnostics.map(mapDiagnosticRow) });
});

scanRoutes.post('/:id/cancel', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scan = db
    .prepare('SELECT id FROM scan_sessions WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!scan) {
    res.status(404).json({ error: 'Scan session not found.' });
    return;
  }

  const cancelled = cancelScanExecution(String(req.params.id));
  res.json({ cancelled });
});

scanRoutes.get('/:id/findings', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scan = db
    .prepare('SELECT id FROM scan_sessions WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!scan) {
    res.status(404).json({ error: 'Scan session not found.' });
    return;
  }

  const rows = db
    .prepare(
      `SELECT f.*, p.name AS project_name
       FROM findings f
       JOIN projects p ON p.id = f.project_id
       WHERE f.scan_id = ? AND f.user_id = ?
       ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, f.file_path ASC, f.start_line ASC`
    )
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  const diagnostics = db
    .prepare('SELECT * FROM scan_diagnostics WHERE scan_id = ? AND user_id = ? ORDER BY file_path ASC, line ASC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({
    findings: rows.map(mapFindingRow),
    diagnostics: diagnostics.map(mapDiagnosticRow),
  });
});

export function mapFindingRow(row: Record<string, unknown>) {
  const rawSnippet = row.code_snippet ? String(row.code_snippet) : '';
  const safeSnippet = sanitizeScannerSnippet(rawSnippet);

  const rawEvidence = row.redacted_evidence ? String(row.redacted_evidence) : null;
  const safeEvidence =
    rawEvidence &&
    !isAuthPlaceholderText(rawEvidence) &&
    !/^Also flagged by\s+/i.test(rawEvidence.trim())
      ? rawEvidence
      : null;

  let contributingScanners: string[] = [];
  try {
    const parsed = JSON.parse(String(row.contributing_scanners_json || '[]'));
    if (Array.isArray(parsed) && parsed.length > 0) {
      contributingScanners = parsed.map(String);
    }
  } catch {
    contributingScanners = [];
  }
  if (contributingScanners.length === 0) {
    contributingScanners = [String(row.scanner_name)];
  }

  let scannerEvidence: Array<Record<string, unknown>> = [];
  try {
    const parsed = JSON.parse(String(row.scanner_evidence_json || '[]'));
    if (Array.isArray(parsed)) {
      scannerEvidence = parsed;
    }
  } catch {
    scannerEvidence = [];
  }
  if (scannerEvidence.length === 0) {
    scannerEvidence = [
      {
        scannerName: String(row.scanner_name),
        ruleId: String(row.rule_id),
        detectionSource: String(row.detection_source),
        title: String(row.title),
        description: String(row.description),
        severity: String(row.severity),
        confidence: String(row.confidence),
        startLine: Number(row.start_line),
        endLine: Number(row.end_line),
        startCol: row.start_col != null ? Number(row.start_col) : null,
        endCol: row.end_col != null ? Number(row.end_col) : null,
        redactedEvidence: safeEvidence,
      },
    ];
  }

  const category = String(row.category);
  const cweId = row.cwe_id ? String(row.cwe_id) : null;
  const recommendation = String(row.recommendation || '');

  return {
    id: String(row.id),
    scanId: String(row.scan_id),
    projectId: String(row.project_id),
    projectName: row.project_name ? String(row.project_name) : undefined,
    userId: String(row.user_id),
    fingerprint: String(row.fingerprint),
    canonicalKey: row.canonical_key ? String(row.canonical_key) : String(row.fingerprint),
    scannerName: String(row.scanner_name),
    detectionSource: String(row.detection_source),
    ruleId: String(row.rule_id),
    title: String(row.title),
    description: String(row.description),
    category,
    severity: String(row.severity),
    confidence: String(row.confidence),
    cweId,
    owaspCategory: row.owasp_category ? String(row.owasp_category) : null,
    filePath: String(row.file_path),
    startLine: Number(row.start_line),
    endLine: Number(row.end_line),
    startCol: row.start_col != null ? Number(row.start_col) : null,
    endCol: row.end_col != null ? Number(row.end_col) : null,
    language: String(row.language),
    codeSnippet: safeSnippet,
    redactedEvidence: safeEvidence,
    recommendation,
    references: JSON.parse(String(row.references_json || '[]')),
    contributingScanners,
    scannerEvidence,
    guidance: buildFindingGuidance({ category, cweId, recommendation }),
    remediationStatus: String(row.remediation_status),
    detectedAt: String(row.detected_at),
  };
}
