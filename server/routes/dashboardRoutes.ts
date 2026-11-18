import { Router } from 'express';
import type { DashboardStats } from '../../shared/types.ts';
import { requireAuth, type AuthenticatedRequest } from '../auth/authMiddleware.ts';
import { getDb } from '../database/db.ts';

export const dashboardRoutes = Router();
dashboardRoutes.use(requireAuth);

dashboardRoutes.get('/stats', (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const userId = req.auth!.userId;

  const projectCountRow = db
    .prepare('SELECT COUNT(*) AS cnt FROM projects WHERE user_id = ?')
    .get(userId) as { cnt: number };

  const scanCountRow = db
    .prepare('SELECT COUNT(*) AS cnt FROM scan_sessions WHERE user_id = ?')
    .get(userId) as { cnt: number };

  // Aggregate findings strictly across the latest scan per project so rescans reflect current project state accurately
  const latestFindingsStats = db
    .prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN f.severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) AS high,
         SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) AS medium,
         SUM(CASE WHEN f.severity = 'Low' THEN 1 ELSE 0 END) AS low,
         SUM(CASE WHEN f.severity = 'Informational' THEN 1 ELSE 0 END) AS info,
         SUM(CASE WHEN f.remediation_status = 'remediated' THEN 1 ELSE 0 END) AS remediated
       FROM findings f
       WHERE f.user_id = ?
         AND f.scan_id = (
           SELECT s.id FROM scan_sessions s
           WHERE s.project_id = f.project_id AND s.user_id = f.user_id
           ORDER BY CASE WHEN s.status IN ('completed', 'partial') THEN 0 ELSE 1 END, s.started_at DESC, s.rowid DESC
           LIMIT 1
         )`
    )
    .get(userId) as Record<string, number | null>;

  const categoryRows = db
    .prepare(
      `SELECT f.category, COUNT(*) AS count
       FROM findings f
       WHERE f.user_id = ?
         AND f.scan_id = (
           SELECT s.id FROM scan_sessions s
           WHERE s.project_id = f.project_id AND s.user_id = f.user_id
           ORDER BY CASE WHEN s.status IN ('completed', 'partial') THEN 0 ELSE 1 END, s.started_at DESC, s.rowid DESC
           LIMIT 1
         )
       GROUP BY f.category
       ORDER BY count DESC
       LIMIT 8`
    )
    .all(userId) as Array<{ category: string; count: number }>;

  const activityRows = db
    .prepare(
      `SELECT substr(started_at, 1, 10) AS date,
              COUNT(*) AS scans,
              SUM(total_findings) AS findings
       FROM scan_sessions
       WHERE user_id = ?
       GROUP BY substr(started_at, 1, 10)
       ORDER BY date ASC
       LIMIT 14`
    )
    .all(userId) as Array<{ date: string; scans: number; findings: number }>;

  const recentScanRows = db
    .prepare(
      `SELECT s.*, p.name AS project_name
       FROM scan_sessions s
       JOIN projects p ON p.id = s.project_id
       WHERE s.user_id = ?
       ORDER BY s.started_at DESC
       LIMIT 6`
    )
    .all(userId) as Array<Record<string, unknown>>;

  const stats: DashboardStats = {
    totalProjects: Number(projectCountRow?.cnt || 0),
    totalScans: Number(scanCountRow?.cnt || 0),
    totalVulnerabilities: Number(latestFindingsStats?.total || 0),
    criticalFindings: Number(latestFindingsStats?.critical || 0),
    highFindings: Number(latestFindingsStats?.high || 0),
    mediumFindings: Number(latestFindingsStats?.medium || 0),
    lowFindings: Number(latestFindingsStats?.low || 0),
    infoFindings: Number(latestFindingsStats?.info || 0),
    remediatedFindings: Number(latestFindingsStats?.remediated || 0),
    findingsByCategory: categoryRows,
    scanActivity: activityRows.map((a) => ({
      date: a.date,
      scans: Number(a.scans),
      findings: Number(a.findings || 0),
    })),
    recentScans: recentScanRows.map((s) => ({
      id: String(s.id),
      projectId: String(s.project_id),
      projectName: String(s.project_name),
      userId: String(s.user_id),
      status: s.status as DashboardStats['recentScans'][0]['status'],
      triggerType: s.trigger_type as 'manual' | 'revalidation',
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
  };

  res.json({ stats });
});
