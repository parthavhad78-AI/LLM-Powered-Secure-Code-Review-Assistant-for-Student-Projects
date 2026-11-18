import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';
import { generateAssessmentReport } from '../reports/reportService.ts';
import { assertPathInsideRoot } from '../scanners/security/fileSecurity.ts';

export const reportRoutes = Router();
reportRoutes.use(requireAuth, requireCsrf);

reportRoutes.get('/', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT r.*, p.name AS project_name
       FROM reports r
       JOIN projects p ON p.id = r.project_id
       WHERE r.user_id = ?
       ORDER BY r.created_at DESC
       LIMIT 50`
    )
    .all(req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({
    reports: rows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      projectId: String(r.project_id),
      projectName: String(r.project_name),
      scanId: r.scan_id ? String(r.scan_id) : null,
      title: String(r.title),
      format: r.format,
      summary: JSON.parse(String(r.summary_json || '{}')),
      createdAt: String(r.created_at),
    })),
  });
});

reportRoutes.post('/', async (req: AuthenticatedRequest, res) => {
  const { projectId, scanId, format, title } = req.body || {};
  if (!projectId || typeof projectId !== 'string') {
    res.status(400).json({ error: 'projectId is required.' });
    return;
  }
  if (format !== 'pdf' && format !== 'csv') {
    res.status(400).json({ error: 'format must be either "pdf" or "csv".' });
    return;
  }

  try {
    const report = await generateAssessmentReport({
      userId: req.auth!.userId,
      projectId,
      scanId: scanId ? String(scanId) : null,
      format,
      title: title ? String(title) : undefined,
    });
    res.status(201).json({ report });
  } catch (err) {
    res.status(400).json({
      error: err instanceof Error ? err.message : 'Failed to generate security report.',
    });
  }
});

reportRoutes.get('/:id/download', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const row = db
    .prepare('SELECT * FROM reports WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

  if (!row) {
    res.status(404).json({ error: 'Report not found.' });
    return;
  }

  const userDir = path.resolve(
    process.cwd(),
    'data',
    'reports',
    req.auth!.userId.replace(/[^a-zA-Z0-9_-]/g, '')
  );
  const absPath = assertPathInsideRoot(userDir, String(row.file_path));

  if (!fs.existsSync(absPath)) {
    res.status(404).json({ error: 'Report file no longer exists on disk.' });
    return;
  }

  const safeTitle = String(row.title)
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .slice(0, 64);
  const ext = row.format === 'csv' ? 'csv' : 'pdf';
  res.setHeader('Content-Type', ext === 'csv' ? 'text/csv; charset=utf-8' : 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}.${ext}"`);
  fs.createReadStream(absPath).pipe(res);
});
