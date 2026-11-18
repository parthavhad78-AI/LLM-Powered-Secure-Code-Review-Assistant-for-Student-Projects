import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ScanDiagnostic, ScannerHealth, ScanSession, ScanStatus } from '../../shared/types.ts';
import { getDb } from '../database/db.ts';
import { banditAdapter } from './adapters/banditAdapter.ts';
import { customAdapter, type ScannerAdapter, type ScannerAdapterResult } from './adapters/customAdapter.ts';
import { eslintAdapter } from './adapters/eslintAdapter.ts';
import { gitleaksAdapter } from './adapters/gitleaksAdapter.ts';
import { osvAdapter } from './adapters/osvAdapter.ts';
import { semgrepAdapter } from './adapters/semgrepAdapter.ts';
import {
  deduplicateDiagnostics,
  deduplicateFindings,
  normalizeFinding,
  type NormalizedFinding,
  type RawScanDiagnostic,
} from './normalization/normalizer.ts';
import {
  cleanupTempDir,
  collectDirectoryFiles,
  createTempScanWorkspace,
  detectFileLanguage,
} from './security/fileSecurity.ts';

const SCANNER_REGISTRY: ScannerAdapter[] = [
  customAdapter,
  banditAdapter,
  semgrepAdapter,
  gitleaksAdapter,
  eslintAdapter,
  osvAdapter,
];

const MAX_SNAPSHOT_FILE_BYTES = 512 * 1024; // 512 KB per text source snapshot

const activeScanControllers = new Map<string, AbortController>();

export function getRegisteredScanners(): ScannerAdapter[] {
  return SCANNER_REGISTRY;
}

export async function getAllScannerHealth(): Promise<ScannerHealth[]> {
  return Promise.all(SCANNER_REGISTRY.map((adapter) => adapter.checkHealth()));
}

export async function runWithConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  limit: number
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let nextIdx = 0;

  async function worker(): Promise<void> {
    while (nextIdx < tasks.length) {
      const idx = nextIdx++;
      results[idx] = await tasks[idx]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export function cancelScanExecution(scanId: string): boolean {
  const controller = activeScanControllers.get(scanId);
  if (controller) {
    controller.abort();
    return true;
  }
  return false;
}

function captureWorkspaceSnapshots(tempWorkspace: string): Array<{
  filePath: string;
  language: string;
  sha256: string;
  sizeBytes: number;
  content: string;
}> {
  const files = collectDirectoryFiles(tempWorkspace);
  const snapshots: Array<{
    filePath: string;
    language: string;
    sha256: string;
    sizeBytes: number;
    content: string;
  }> = [];

  for (const relPath of files) {
    const absPath = path.join(tempWorkspace, relPath);
    try {
      const stat = fs.statSync(absPath);
      if (stat.size > MAX_SNAPSHOT_FILE_BYTES) continue;
      const buf = fs.readFileSync(absPath);
      // Skip binary files containing null bytes
      if (buf.includes(0)) continue;
      const content = buf.toString('utf8');
      const { language } = detectFileLanguage(relPath);
      const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
      snapshots.push({
        filePath: relPath,
        language,
        sha256,
        sizeBytes: buf.length,
        content,
      });
    } catch {
      // Skip unreadable files without failing scan
    }
  }
  return snapshots;
}

export async function executeProjectScan(params: {
  userId: string;
  projectId: string;
  sourcePath: string;
  scanners?: string[];
  triggerType?: 'manual' | 'revalidation';
}): Promise<ScanSession> {
  const db = getDb();
  const scanId = crypto.randomUUID();
  const startedAt = new Date().toISOString();

  const requestedNames =
    params.scanners && params.scanners.length > 0
      ? params.scanners
      : SCANNER_REGISTRY.map((s) => s.name);

  const selectedAdapters = SCANNER_REGISTRY.filter((a) => requestedNames.includes(a.name));
  if (selectedAdapters.length === 0) {
    selectedAdapters.push(customAdapter);
  }

  const projectProvenance = db
    .prepare('SELECT github_repo_url, github_branch, github_commit_sha FROM projects WHERE id = ? AND user_id = ?')
    .get(params.projectId, params.userId) as
    | { github_repo_url: string | null; github_branch: string | null; github_commit_sha: string | null }
    | undefined;

  const repoUrl = projectProvenance?.github_repo_url || null;
  const repoBranch = projectProvenance?.github_branch || null;
  const commitSha = projectProvenance?.github_commit_sha || null;

  db.prepare(
    `INSERT INTO scan_sessions (id, project_id, user_id, status, trigger_type, scanners_requested_json, repo_url, repo_branch, commit_sha, started_at)
     VALUES (?, ?, ?, 'running', ?, ?, ?, ?, ?, ?)`
  ).run(
    scanId,
    params.projectId,
    params.userId,
    params.triggerType || 'manual',
    JSON.stringify(selectedAdapters.map((a) => a.name)),
    repoUrl,
    repoBranch,
    commitSha,
    startedAt
  );

  const controller = new AbortController();
  activeScanControllers.set(scanId, controller);

  const timeoutMs = Number(process.env.SCANNER_TIMEOUT_MS || 30000);
  const concurrency = Math.max(1, Number(process.env.SCANNER_CONCURRENCY || 3));

  let tempWorkspace = '';
  try {
    tempWorkspace = createTempScanWorkspace(scanId, params.sourcePath);
    const snapshots = captureWorkspaceSnapshots(tempWorkspace);

    const adapterTasks = selectedAdapters.map(
      (adapter) => async (): Promise<ScannerAdapterResult> => {
        try {
          return await adapter.scan(tempWorkspace, {
            timeoutMs,
            signal: controller.signal,
          });
        } catch (err) {
          return {
            scannerName: adapter.name,
            available: false,
            version: null,
            status: 'failed',
            durationMs: 0,
            findings: [],
            diagnostics: [],
            errorMessage: err instanceof Error ? err.message : 'Unexpected scanner failure.',
          };
        }
      }
    );

    const adapterResults = await runWithConcurrency(adapterTasks, concurrency);

    // Normalize and deduplicate findings across all successful/partial scanners
    const normalizedAll: NormalizedFinding[] = [];
    const rawDiagnostics: RawScanDiagnostic[] = [];
    for (const res of adapterResults) {
      for (const raw of res.findings) {
        normalizedAll.push(normalizeFinding(raw, params.projectId));
      }
      for (const diag of res.diagnostics || []) {
        rawDiagnostics.push(diag);
      }
    }

    const deduped = deduplicateFindings(normalizedAll);
    const dedupedDiagnostics = deduplicateDiagnostics(rawDiagnostics);

    // Count severities
    const counts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0,
    };
    for (const f of deduped) {
      counts[f.severity]++;
    }

    const allCancelled = controller.signal.aborted;
    const anyCompleted = adapterResults.some((r) => r.status === 'completed');
    const anyFailedOrUnavailable = adapterResults.some(
      (r) => r.status === 'failed' || r.status === 'timed_out'
    );

    const finalStatus: ScanStatus = allCancelled
      ? 'cancelled'
      : !anyCompleted
        ? 'failed'
        : anyFailedOrUnavailable
          ? 'partial'
          : 'completed';

    const completedAt = new Date().toISOString();
    const persistedDiagnostics: ScanDiagnostic[] = [];

    const saveTx = db.transaction(() => {
      const insertSnapshot = db.prepare(
        `INSERT OR IGNORE INTO scan_file_snapshots
         (id, scan_id, project_id, user_id, file_path, language, sha256, size_bytes, content, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const snap of snapshots) {
        insertSnapshot.run(
          crypto.randomUUID(),
          scanId,
          params.projectId,
          params.userId,
          snap.filePath,
          snap.language,
          snap.sha256,
          snap.sizeBytes,
          snap.content,
          completedAt
        );
      }

      const insertScannerRes = db.prepare(
        `INSERT INTO scanner_results
         (id, scan_id, scanner_name, available, version, status, duration_ms, findings_count, error_message, install_hint, executed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );

      for (const sr of adapterResults) {
        insertScannerRes.run(
          crypto.randomUUID(),
          scanId,
          sr.scannerName,
          sr.available ? 1 : 0,
          sr.version,
          sr.status,
          sr.durationMs,
          sr.findings.length,
          sr.errorMessage || null,
          sr.installHint || null,
          completedAt
        );
      }

      const insertDiag = db.prepare(
        `INSERT INTO scan_diagnostics
         (id, scan_id, project_id, user_id, canonical_key, scanner_name, contributing_scanners_json, scanner_messages_json,
          file_path, line, column_num, severity, kind, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(scan_id, canonical_key) DO UPDATE SET
           contributing_scanners_json = excluded.contributing_scanners_json,
           scanner_messages_json = excluded.scanner_messages_json,
           line = excluded.line,
           column_num = excluded.column_num,
           severity = excluded.severity,
           message = excluded.message`
      );
      for (const d of dedupedDiagnostics) {
        const diagId = crypto.randomUUID();
        insertDiag.run(
          diagId,
          scanId,
          params.projectId,
          params.userId,
          d.canonicalKey,
          d.scannerName,
          JSON.stringify(d.contributingScanners),
          JSON.stringify(d.scannerMessages),
          d.filePath,
          Math.max(1, d.line),
          d.column ?? null,
          d.severity,
          d.kind,
          d.message,
          completedAt
        );
        persistedDiagnostics.push({
          id: diagId,
          scanId,
          projectId: params.projectId,
          canonicalKey: d.canonicalKey,
          scannerName: d.scannerName,
          contributingScanners: d.contributingScanners,
          scannerMessages: d.scannerMessages,
          filePath: d.filePath,
          line: Math.max(1, d.line),
          column: d.column ?? null,
          severity: d.severity,
          kind: d.kind,
          message: d.message,
          createdAt: completedAt,
        });
      }

      const insertFinding = db.prepare(
        `INSERT INTO findings
         (id, scan_id, project_id, user_id, fingerprint, canonical_key, scanner_name, detection_source, rule_id,
          title, description, category, severity, confidence, cwe_id, owasp_category, file_path,
          start_line, end_line, start_col, end_col, language, code_snippet, redacted_evidence,
          recommendation, references_json, contributing_scanners_json, scanner_evidence_json,
          remediation_status, detected_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
         ON CONFLICT(scan_id, canonical_key) DO UPDATE SET
           severity = excluded.severity,
           start_line = excluded.start_line,
           end_line = excluded.end_line,
           start_col = COALESCE(findings.start_col, excluded.start_col),
           end_col = COALESCE(findings.end_col, excluded.end_col),
           contributing_scanners_json = excluded.contributing_scanners_json,
           scanner_evidence_json = excluded.scanner_evidence_json,
           references_json = excluded.references_json`
      );

      for (const f of deduped) {
        insertFinding.run(
          crypto.randomUUID(),
          scanId,
          params.projectId,
          params.userId,
          f.fingerprint,
          f.canonicalKey,
          f.scannerName,
          f.detectionSource,
          f.ruleId,
          f.title,
          f.description,
          f.category,
          f.severity,
          f.confidence,
          f.cweId,
          f.owaspCategory,
          f.filePath,
          f.startLine,
          f.endLine,
          f.startCol,
          f.endCol,
          f.language,
          f.codeSnippet,
          f.redactedEvidence,
          f.recommendation,
          JSON.stringify(f.references),
          JSON.stringify(f.contributingScanners),
          JSON.stringify(f.scannerEvidence),
          completedAt
        );
      }

      db.prepare(
        `UPDATE scan_sessions
         SET status = ?, total_findings = ?, critical_count = ?, high_count = ?, medium_count = ?,
             low_count = ?, info_count = ?, completed_at = ?
         WHERE id = ?`
      ).run(
        finalStatus,
        deduped.length,
        counts.Critical,
        counts.High,
        counts.Medium,
        counts.Low,
        counts.Informational,
        completedAt,
        scanId
      );
    });

    saveTx();

    return {
      id: scanId,
      projectId: params.projectId,
      userId: params.userId,
      status: finalStatus,
      triggerType: params.triggerType || 'manual',
      scannersRequested: selectedAdapters.map((a) => a.name),
      totalFindings: deduped.length,
      criticalCount: counts.Critical,
      highCount: counts.High,
      mediumCount: counts.Medium,
      lowCount: counts.Low,
      infoCount: counts.Informational,
      startedAt,
      completedAt,
      errorMessage: null,
      repoUrl,
      repoBranch,
      commitSha,
      scannerResults: adapterResults.map((sr, i) => ({
        id: `sr-${i}`,
        scanId,
        scannerName: sr.scannerName,
        available: sr.available,
        version: sr.version,
        status: sr.status,
        durationMs: sr.durationMs,
        findingsCount: sr.findings.length,
        errorMessage: sr.errorMessage || null,
        installHint: sr.installHint || null,
        executedAt: completedAt,
      })),
      diagnostics: persistedDiagnostics,
    };
  } catch (err) {
    const completedAt = new Date().toISOString();
    const message = err instanceof Error ? err.message : 'Scan execution failed.';
    db.prepare(
      `UPDATE scan_sessions SET status = 'failed', completed_at = ?, error_message = ? WHERE id = ?`
    ).run(completedAt, message, scanId);
    throw err;
  } finally {
    activeScanControllers.delete(scanId);
    cleanupTempDir(tempWorkspace);
  }
}
