import { Router } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Project, ProjectFile } from '../../shared/types.ts';
import { requireAuth, requireCsrf, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';
import {
  assertPathInsideRoot,
  FileSecurityError,
  getProjectSourceDir,
  getProjectStorageRoot,
  MAX_ARCHIVE_BYTES,
  safeExtractZipToProject,
  safeStoreUploadedFiles,
  type StoredFileMeta,
} from '../scanners/security/fileSecurity.ts';

export const projectRoutes = Router();
projectRoutes.use(requireAuth, requireCsrf);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_ARCHIVE_BYTES,
    files: 300,
  },
});

function mapProjectRow(row: Record<string, unknown>): Project {
  return {
    id: String(row.id),
    userId: String(row.user_id),
    name: String(row.name),
    description: String(row.description || ''),
    primaryLanguage: row.primary_language ? String(row.primary_language) : null,
    languages: JSON.parse(String(row.languages_json || '[]')),
    fileCount: Number(row.file_count || 0),
    totalBytes: Number(row.total_bytes || 0),
    importMethod: (row.import_method as Project['importMethod']) || 'upload',
    githubRepoUrl: row.github_repo_url ? String(row.github_repo_url) : null,
    githubOwner: row.github_owner ? String(row.github_owner) : null,
    githubRepo: row.github_repo ? String(row.github_repo) : null,
    githubBranch: row.github_branch ? String(row.github_branch) : null,
    githubCommitSha: row.github_commit_sha ? String(row.github_commit_sha) : null,
    githubIsPrivate: Boolean(row.github_is_private),
    lastImportedAt: row.last_imported_at ? String(row.last_imported_at) : null,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    lastScanAt: row.last_scan_at ? String(row.last_scan_at) : null,
    openFindingsCount: row.open_findings_count !== undefined ? Number(row.open_findings_count) : undefined,
  };
}

projectRoutes.get('/', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT p.*,
              (SELECT MAX(started_at) FROM scan_sessions s WHERE s.project_id = p.id) AS last_scan_at,
              (SELECT COUNT(*) FROM findings f
               WHERE f.project_id = p.id
                 AND f.scan_id = (SELECT id FROM scan_sessions s2 WHERE s2.project_id = p.id ORDER BY s2.started_at DESC LIMIT 1)
                 AND f.remediation_status IN ('open', 'in_review')) AS open_findings_count
       FROM projects p
       WHERE p.user_id = ?
       ORDER BY p.updated_at DESC`
    )
    .all(req.auth!.userId) as Array<Record<string, unknown>>;

  res.json({ projects: rows.map(mapProjectRow) });
});

projectRoutes.post('/', (req: AuthenticatedRequest, res) => {
  const { name, description } = req.body || {};
  const cleanName = String(name || '').trim();
  const cleanDesc = String(description || '').trim();

  if (cleanName.length < 2 || cleanName.length > 80) {
    res.status(400).json({ error: 'Project name must be between 2 and 80 characters.' });
    return;
  }
  if (cleanDesc.length > 500) {
    res.status(400).json({ error: 'Description cannot exceed 500 characters.' });
    return;
  }

  const projectId = crypto.randomUUID();
  const sourceDir = getProjectSourceDir(req.auth!.userId, projectId);
  fs.mkdirSync(sourceDir, { recursive: true });
  const now = new Date().toISOString();

  const db = getDb();
  db.prepare(
    `INSERT INTO projects (id, user_id, name, description, primary_language, languages_json, source_path, file_count, total_bytes, created_at, updated_at)
     VALUES (?, ?, ?, ?, NULL, '[]', ?, 0, 0, ?, ?)`
  ).run(projectId, req.auth!.userId, cleanName, cleanDesc, sourceDir, now, now);

  const created = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId) as Record<string, unknown>;
  res.status(201).json({ project: mapProjectRow(created) });
});

projectRoutes.get('/:id', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const projRow = db
    .prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

  if (!projRow) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const fileRows = db
    .prepare('SELECT * FROM project_files WHERE project_id = ? ORDER BY relative_path ASC')
    .all(req.params.id) as Array<Record<string, unknown>>;

  const files: ProjectFile[] = fileRows.map((f) => ({
    id: String(f.id),
    projectId: String(f.project_id),
    relativePath: String(f.relative_path),
    language: String(f.language),
    sizeBytes: Number(f.size_bytes),
    sha256: String(f.sha256),
    isSupported: Boolean(f.is_supported),
    createdAt: String(f.created_at),
  }));

  const scans = db
    .prepare('SELECT * FROM scan_sessions WHERE project_id = ? AND user_id = ? ORDER BY started_at DESC LIMIT 20')
    .all(req.params.id, req.auth!.userId) as Array<Record<string, unknown>>;

  const unsupportedLanguages = Array.from(
    new Set(files.filter((f) => !f.isSupported && f.language !== 'Other').map((f) => f.language))
  );

  res.json({
    project: mapProjectRow(projRow),
    files,
    scans: scans.map((s) => ({
      id: String(s.id),
      projectId: String(s.project_id),
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
    unsupportedLanguages,
  });
});

projectRoutes.put('/:id', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const existing = db
    .prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

  if (!existing) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const cleanName = String(req.body?.name ?? existing.name).trim();
  const cleanDesc = String(req.body?.description ?? existing.description).trim();

  if (cleanName.length < 2 || cleanName.length > 80) {
    res.status(400).json({ error: 'Project name must be between 2 and 80 characters.' });
    return;
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE projects SET name = ?, description = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(
    cleanName,
    cleanDesc,
    now,
    req.params.id,
    req.auth!.userId
  );

  const updated = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id) as Record<string, unknown>;
  res.json({ project: mapProjectRow(updated) });
});

projectRoutes.delete('/:id', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const existing = db
    .prepare('SELECT id FROM projects WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!existing) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  db.prepare('DELETE FROM projects WHERE id = ? AND user_id = ?').run(req.params.id, req.auth!.userId);

  try {
    const storageRoot = getProjectStorageRoot(req.auth!.userId, String(req.params.id));
    fs.rmSync(storageRoot, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup
  }

  res.json({ ok: true });
});

projectRoutes.post('/:id/upload', upload.array('files', 300), (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const existing = db
    .prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

  if (!existing) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const uploadedFiles = (req.files as Express.Multer.File[] | undefined) || [];
  if (uploadedFiles.length === 0) {
    res.status(400).json({ error: 'Please select a ZIP archive or source files to upload.' });
    return;
  }

  const replaceExisting = String(req.body?.replace || 'true') !== 'false';
  const sourceDir = getProjectSourceDir(req.auth!.userId, String(req.params.id));

  try {
    if (replaceExisting) {
      fs.rmSync(sourceDir, { recursive: true, force: true });
      fs.mkdirSync(sourceDir, { recursive: true });
    }

    let storedMeta: StoredFileMeta[] = [];
    let importMethod: 'zip' | 'upload' = 'upload';

    if (
      uploadedFiles.length === 1 &&
      path.extname(uploadedFiles[0].originalname).toLowerCase() === '.zip'
    ) {
      importMethod = 'zip';
      storedMeta = safeExtractZipToProject(uploadedFiles[0].buffer, sourceDir);
    } else {
      const hasZip = uploadedFiles.some(
        (f) => path.extname(f.originalname).toLowerCase() === '.zip'
      );
      if (hasZip) {
        res.status(400).json({ error: 'Upload either a single ZIP archive or individual source files.' });
        return;
      }
      storedMeta = safeStoreUploadedFiles(
        uploadedFiles.map((f) => ({ originalname: f.originalname, buffer: f.buffer })),
        sourceDir
      );
    }

    const now = new Date().toISOString();
    const tx = db.transaction(() => {
      if (replaceExisting) {
        db.prepare('DELETE FROM project_files WHERE project_id = ?').run(req.params.id);
      }

      const upsertFile = db.prepare(
        `INSERT INTO project_files (id, project_id, relative_path, language, size_bytes, sha256, is_supported, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(project_id, relative_path) DO UPDATE SET
           language = excluded.language,
           size_bytes = excluded.size_bytes,
           sha256 = excluded.sha256,
           is_supported = excluded.is_supported`
      );

      for (const meta of storedMeta) {
        upsertFile.run(
          crypto.randomUUID(),
          req.params.id,
          meta.relativePath,
          meta.language,
          meta.sizeBytes,
          meta.sha256,
          meta.isSupported ? 1 : 0,
          now
        );
      }

      const allProjectFiles = db
        .prepare('SELECT language, size_bytes FROM project_files WHERE project_id = ?')
        .all(req.params.id) as Array<{ language: string; size_bytes: number }>;

      const langBytes = new Map<string, number>();
      let totalBytes = 0;
      for (const f of allProjectFiles) {
        totalBytes += f.size_bytes;
        if (!['JSON / Config', 'Text / Manifest', 'Lockfile', 'Environment Config', 'Other'].includes(f.language)) {
          langBytes.set(f.language, (langBytes.get(f.language) || 0) + f.size_bytes);
        }
      }

      const sortedLangs = Array.from(langBytes.entries())
        .sort((a, b) => b[1] - a[1])
        .map((e) => e[0]);

      const allLangs = Array.from(new Set(allProjectFiles.map((f) => f.language)));
      const primaryLanguage = sortedLangs[0] || allLangs[0] || null;

      db.prepare(
        `UPDATE projects
         SET primary_language = ?, languages_json = ?, file_count = ?, total_bytes = ?,
             import_method = ?, last_imported_at = ?, updated_at = ?
         WHERE id = ? AND user_id = ?`
      ).run(
        primaryLanguage,
        JSON.stringify(allLangs),
        allProjectFiles.length,
        totalBytes,
        importMethod,
        now,
        now,
        req.params.id,
        req.auth!.userId
      );
    });

    tx();

    const updated = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id) as Record<string, unknown>;
    res.json({
      project: mapProjectRow(updated),
      uploadedCount: storedMeta.length,
    });
  } catch (err) {
    if (err instanceof FileSecurityError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to process uploaded project files.' });
  }
});

projectRoutes.get('/:id/file', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const project = db
    .prepare('SELECT id FROM projects WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.auth!.userId);

  if (!project) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  const relPath = String(req.query.path || '');
  if (!relPath) {
    res.status(400).json({ error: 'File path query parameter is required.' });
    return;
  }

  try {
    const sourceDir = getProjectSourceDir(req.auth!.userId, String(req.params.id));
    const absFile = assertPathInsideRoot(sourceDir, relPath);
    if (!fs.existsSync(absFile)) {
      res.status(404).json({ error: 'File not found in project.' });
      return;
    }
    const content = fs.readFileSync(absFile, 'utf8');
    res.json({ relativePath: relPath, content });
  } catch (err) {
    if (err instanceof FileSecurityError) {
      res.status(err.statusCode).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Failed to read file.' });
  }
});
