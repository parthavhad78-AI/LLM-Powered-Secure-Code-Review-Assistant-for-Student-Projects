import { Router } from 'express';
import { generateFixWithGemini } from '../ai/aiService.ts';
import { GeminiServiceError } from '../ai/geminiClient.ts';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';
import {
  approveAndApplyRemediation,
  getOwnedRemediation,
  rejectRemediation,
  RemediationError,
  validateRemediationFix,
} from '../remediation/remediationService.ts';
import {
  getFindingFullSnapshot,
  getFindingSourceContext,
} from '../scanners/findingGuidance.ts';
import { mapDiagnosticRow, mapFindingRow } from './scanRoutes.ts';

export const findingRoutes = Router();
findingRoutes.use(requireAuth, requireCsrf);

const LATEST_SCAN_SUBQUERY = `(
  SELECT s.id FROM scan_sessions s
  WHERE s.project_id = f.project_id AND s.user_id = f.user_id
  ORDER BY CASE WHEN s.status IN ('completed', 'partial') THEN 0 ELSE 1 END, s.started_at DESC, s.rowid DESC
  LIMIT 1
)`;

const LATEST_DIAG_SCAN_SUBQUERY = `(
  SELECT s.id FROM scan_sessions s
  WHERE s.project_id = d.project_id AND s.user_id = d.user_id
  ORDER BY CASE WHEN s.status IN ('completed', 'partial') THEN 0 ELSE 1 END, s.started_at DESC, s.rowid DESC
  LIMIT 1
)`;

// Cross-project findings list with search & filters (default: latest scan per project to prevent cross-scan duplication)
findingRoutes.get('/findings', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const { projectId, scanId, scope, severity, category, scanner, language, status, q } = req.query;

  const where: string[] = ['f.user_id = ?'];
  const params: unknown[] = [req.auth!.userId];

  const diagWhere: string[] = ['d.user_id = ?'];
  const diagParams: unknown[] = [req.auth!.userId];

  if (scanId && typeof scanId === 'string' && scanId !== 'all') {
    where.push('f.scan_id = ?');
    params.push(scanId);
    diagWhere.push('d.scan_id = ?');
    diagParams.push(scanId);
  } else if (scope !== 'all') {
    where.push(`f.scan_id = ${LATEST_SCAN_SUBQUERY}`);
    diagWhere.push(`d.scan_id = ${LATEST_DIAG_SCAN_SUBQUERY}`);
  }

  if (projectId && typeof projectId === 'string' && projectId !== 'all') {
    where.push('f.project_id = ?');
    params.push(projectId);
    diagWhere.push('d.project_id = ?');
    diagParams.push(projectId);
  }
  if (severity && typeof severity === 'string' && severity !== 'all') {
    where.push('f.severity = ?');
    params.push(severity);
  }
  if (category && typeof category === 'string' && category !== 'all') {
    where.push('f.category = ?');
    params.push(category);
  }
  if (scanner && typeof scanner === 'string' && scanner !== 'all') {
    where.push(
      '(f.scanner_name = ? OR EXISTS (SELECT 1 FROM json_each(f.contributing_scanners_json) WHERE json_each.value = ?))'
    );
    params.push(scanner, scanner);
  }
  if (language && typeof language === 'string' && language !== 'all') {
    where.push('f.language = ?');
    params.push(language);
  }
  if (status && typeof status === 'string' && status !== 'all') {
    where.push('f.remediation_status = ?');
    params.push(status);
  }
  if (q && typeof q === 'string' && q.trim()) {
    where.push('(f.title LIKE ? OR f.file_path LIKE ? OR f.rule_id LIKE ? OR f.description LIKE ?)');
    const like = `%${q.trim()}%`;
    params.push(like, like, like, like);
  }

  const rows = db
    .prepare(
      `SELECT f.*, p.name AS project_name
       FROM findings f
       JOIN projects p ON p.id = f.project_id
       WHERE ${where.join(' AND ')}
       ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, f.file_path ASC, f.start_line ASC
       LIMIT 500`
    )
    .all(...params) as Array<Record<string, unknown>>;

  const diagRows = db
    .prepare(
      `SELECT d.*
       FROM scan_diagnostics d
       WHERE ${diagWhere.join(' AND ')}
       ORDER BY d.file_path ASC, d.line ASC
       LIMIT 200`
    )
    .all(...diagParams) as Array<Record<string, unknown>>;

  const findings = rows.map(mapFindingRow);
  const diagnostics = diagRows.map(mapDiagnosticRow);

  res.json({
    findings,
    diagnostics,
    summary: {
      totalFindings: findings.length,
      critical: findings.filter((f) => f.severity === 'Critical').length,
      high: findings.filter((f) => f.severity === 'High').length,
      medium: findings.filter((f) => f.severity === 'Medium').length,
      low: findings.filter((f) => f.severity === 'Low').length,
      informational: findings.filter((f) => f.severity === 'Informational').length,
      totalDiagnostics: diagnostics.length,
    },
  });
});

findingRoutes.get('/projects/:id/findings', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const project = db
    .prepare('SELECT id FROM projects WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!project) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const { scanId, scope } = req.query;
  const where: string[] = ['f.project_id = ?', 'f.user_id = ?'];
  const params: unknown[] = [req.params.id, req.auth!.userId];
  const diagWhere: string[] = ['d.project_id = ?', 'd.user_id = ?'];
  const diagParams: unknown[] = [req.params.id, req.auth!.userId];

  if (scanId && typeof scanId === 'string' && scanId !== 'all') {
    where.push('f.scan_id = ?');
    params.push(scanId);
    diagWhere.push('d.scan_id = ?');
    diagParams.push(scanId);
  } else if (scope !== 'all') {
    where.push(`f.scan_id = ${LATEST_SCAN_SUBQUERY}`);
    diagWhere.push(`d.scan_id = ${LATEST_DIAG_SCAN_SUBQUERY}`);
  }

  const rows = db
    .prepare(
      `SELECT f.*, p.name AS project_name
       FROM findings f
       JOIN projects p ON p.id = f.project_id
       WHERE ${where.join(' AND ')}
       ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, f.file_path ASC, f.start_line ASC`
    )
    .all(...params) as Array<Record<string, unknown>>;

  const diagRows = db
    .prepare(
      `SELECT d.*
       FROM scan_diagnostics d
       WHERE ${diagWhere.join(' AND ')}
       ORDER BY d.file_path ASC, d.line ASC`
    )
    .all(...diagParams) as Array<Record<string, unknown>>;

  const findings = rows.map(mapFindingRow);
  const diagnostics = diagRows.map(mapDiagnosticRow);

  res.json({
    findings,
    diagnostics,
    summary: {
      totalFindings: findings.length,
      critical: findings.filter((f) => f.severity === 'Critical').length,
      high: findings.filter((f) => f.severity === 'High').length,
      medium: findings.filter((f) => f.severity === 'Medium').length,
      low: findings.filter((f) => f.severity === 'Low').length,
      informational: findings.filter((f) => f.severity === 'Informational').length,
      totalDiagnostics: diagnostics.length,
    },
  });
});

findingRoutes.get('/findings/:id', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT f.*, p.name AS project_name
       FROM findings f
       JOIN projects p ON p.id = f.project_id
       WHERE f.id = ? AND f.user_id = ?`
    )
    .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

  if (!row) {
    res.status(404).json({ error: 'Finding not found.' });
    return;
  }

  const analyses = db
    .prepare('SELECT * FROM ai_analyses WHERE finding_id = ? AND user_id = ? ORDER BY created_at DESC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  const proposals = db
    .prepare('SELECT * FROM remediation_proposals WHERE finding_id = ? AND user_id = ? ORDER BY created_at DESC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  const history = db
    .prepare('SELECT * FROM remediation_history WHERE finding_id = ? AND user_id = ? ORDER BY created_at DESC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  const diagnostics = db
    .prepare(
      `SELECT * FROM scan_diagnostics
       WHERE scan_id = ? AND user_id = ?
       ORDER BY file_path ASC, line ASC`
    )
    .all(String(row.scan_id), req.auth!.userId) as Array<Record<string, unknown>>;

  const sourceContext = getFindingSourceContext({
    findingId: String(req.params.id),
    userId: req.auth!.userId,
    contextRadius: 7,
  });

  res.json({
    finding: mapFindingRow(row),
    sourceContext,
    diagnostics: diagnostics.map(mapDiagnosticRow),
    analyses: analyses.map((a) => ({
      id: String(a.id),
      findingId: String(a.finding_id),
      userId: String(a.user_id),
      modelName: String(a.model_name),
      vulnerabilityMeaning: String(a.vulnerability_meaning),
      whyUnsafe: String(a.why_unsafe),
      exploitationScenario: String(a.exploitation_scenario),
      realWorldImpact: String(a.real_world_impact),
      riskContext: String(a.risk_context),
      secureRecommendation: String(a.secure_recommendation),
      cweOwaspContext: String(a.cwe_owasp_context),
      correctedCodeExample: String(a.corrected_code_example),
      falsePositiveAssessment: String(a.false_positive_assessment),
      falsePositiveReasoning: String(a.false_positive_reasoning),
      uncertaintyNote: String(a.uncertainty_note),
      createdAt: String(a.created_at),
    })),
    remediations: proposals.map((r) => ({
      id: String(r.id),
      findingId: String(r.finding_id),
      projectId: String(r.project_id),
      userId: String(r.user_id),
      filePath: String(r.file_path),
      originalCode: String(r.original_code),
      proposedCode: String(r.proposed_code),
      diffSummary: String(r.diff_summary),
      explanation: String(r.explanation),
      status: String(r.status),
      validationStatus: String(r.validation_status),
      validationSummary: r.validation_summary ? String(r.validation_summary) : null,
      backupPath: r.backup_path ? String(r.backup_path) : null,
      createdAt: String(r.created_at),
      reviewedAt: r.reviewed_at ? String(r.reviewed_at) : null,
      validatedAt: r.validated_at ? String(r.validated_at) : null,
    })),
    history: history.map((h) => ({
      id: String(h.id),
      remediationId: String(h.remediation_id),
      findingId: String(h.finding_id),
      userId: String(h.user_id),
      action: String(h.action),
      details: JSON.parse(String(h.details_json || '{}')),
      createdAt: String(h.created_at),
    })),
  });
});

findingRoutes.get('/findings/:id/source', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const owned = db
    .prepare('SELECT id FROM findings WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!owned) {
    res.status(404).json({ error: 'Finding not found.' });
    return;
  }

  const fullMode = String(req.query.full || '').toLowerCase() === 'true';
  if (fullMode) {
    const fileData = getFindingFullSnapshot({
      findingId: String(req.params.id),
      userId: req.auth!.userId,
    });
    res.json({ file: fileData });
    return;
  }

  const radiusParam = Number(req.query.radius || 7);
  const context = getFindingSourceContext({
    findingId: String(req.params.id),
    userId: req.auth!.userId,
    contextRadius: Number.isFinite(radiusParam) ? radiusParam : 7,
  });
  res.json({ sourceContext: context });
});

findingRoutes.get('/findings/:id/analysis', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const finding = db
    .prepare('SELECT id FROM findings WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!finding) {
    res.status(404).json({ error: 'Finding not found.' });
    return;
  }

  const analyses = db
    .prepare('SELECT * FROM ai_analyses WHERE finding_id = ? AND user_id = ? ORDER BY created_at DESC')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({
    analyses: analyses.map((a) => ({
      id: String(a.id),
      findingId: String(a.finding_id),
      userId: String(a.user_id),
      modelName: String(a.model_name),
      vulnerabilityMeaning: String(a.vulnerability_meaning),
      whyUnsafe: String(a.why_unsafe),
      exploitationScenario: String(a.exploitation_scenario),
      realWorldImpact: String(a.real_world_impact),
      riskContext: String(a.risk_context),
      secureRecommendation: String(a.secure_recommendation),
      cweOwaspContext: String(a.cwe_owasp_context),
      correctedCodeExample: String(a.corrected_code_example),
      falsePositiveAssessment: String(a.false_positive_assessment),
      falsePositiveReasoning: String(a.false_positive_reasoning),
      uncertaintyNote: String(a.uncertainty_note),
      createdAt: String(a.created_at),
    })),
  });
});

findingRoutes.patch('/findings/:id/status', (req: AuthenticatedRequest, res) => {
  const allowed = new Set(['open', 'in_review', 'approved', 'remediated', 'accepted_risk', 'false_positive']);
  const nextStatus = String(req.body?.status || '');
  if (!allowed.has(nextStatus)) {
    res.status(400).json({ error: 'Invalid remediation status.' });
    return;
  }

  const db = getDb();
  const result = db
    .prepare('UPDATE findings SET remediation_status = ? WHERE id = ? AND user_id = ?')
    .run(nextStatus, req.params.id, req.auth!.userId);

  if (result.changes === 0) {
    res.status(404).json({ error: 'Finding not found.' });
    return;
  }

  res.json({ ok: true, status: nextStatus });
});

findingRoutes.post('/findings/:id/fix', async (req: AuthenticatedRequest, res) => {
  try {
    const proposal = await generateFixWithGemini({
      findingId: String(req.params.id),
      userId: req.auth!.userId,
      modelOverride: req.auth!.user.preferredModel,
    });
    res.status(201).json({ remediation: proposal });
  } catch (err) {
    if (err instanceof GeminiServiceError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to generate AI fix proposal.' });
  }
});

findingRoutes.post('/remediations/:id/approve', (req: AuthenticatedRequest, res) => {
  try {
    const proposal = approveAndApplyRemediation(String(req.params.id), req.auth!.userId);
    res.json({ remediation: proposal });
  } catch (err) {
    if (err instanceof RemediationError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to approve and apply fix.' });
  }
});

findingRoutes.post('/remediations/:id/reject', (req: AuthenticatedRequest, res) => {
  try {
    const proposal = rejectRemediation(
      String(req.params.id),
      req.auth!.userId,
      req.body?.reason ? String(req.body.reason) : undefined
    );
    res.json({ remediation: proposal });
  } catch (err) {
    if (err instanceof RemediationError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to reject fix proposal.' });
  }
});

findingRoutes.post('/remediations/:id/validate', async (req: AuthenticatedRequest, res) => {
  try {
    const result = await validateRemediationFix(String(req.params.id), req.auth!.userId);
    res.json(result);
  } catch (err) {
    if (err instanceof RemediationError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to validate fix with static scanners.' });
  }
});

findingRoutes.get('/remediations/:id/download', (req: AuthenticatedRequest, res) => {
  try {
    const proposal = getOwnedRemediation(String(req.params.id), req.auth!.userId);
    const baseName = proposal.filePath.split('/').pop() || 'patched_file.txt';
    res.setHeader('Content-Disposition', `attachment; filename="patched_${baseName}"`);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(proposal.proposedCode);
  } catch (err) {
    if (err instanceof RemediationError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to download patched file.' });
  }
});
