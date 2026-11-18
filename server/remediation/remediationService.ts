import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { RemediationProposal, ValidationStatus } from '../../shared/types.ts';
import { getDb } from '../database/db.ts';
import { executeProjectScan } from '../scanners/scannerManager.ts';
import {
  assertPathInsideRoot,
  getProjectBackupDir,
  getProjectSourceDir,
} from '../scanners/security/fileSecurity.ts';

export class RemediationError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'RemediationError';
    this.statusCode = statusCode;
  }
}

function mapRow(row: Record<string, unknown>): RemediationProposal {
  return {
    id: String(row.id),
    findingId: String(row.finding_id),
    projectId: String(row.project_id),
    userId: String(row.user_id),
    filePath: String(row.file_path),
    originalCode: String(row.original_code),
    proposedCode: String(row.proposed_code),
    diffSummary: String(row.diff_summary),
    explanation: String(row.explanation),
    status: row.status as RemediationProposal['status'],
    validationStatus: row.validation_status as ValidationStatus,
    validationSummary: row.validation_summary ? String(row.validation_summary) : null,
    backupPath: row.backup_path ? String(row.backup_path) : null,
    createdAt: String(row.created_at),
    reviewedAt: row.reviewed_at ? String(row.reviewed_at) : null,
    validatedAt: row.validated_at ? String(row.validated_at) : null,
  };
}

export function getOwnedRemediation(remediationId: string, userId: string): RemediationProposal {
  const db = getDb();
  const row = db
    .prepare('SELECT * FROM remediation_proposals WHERE id = ? AND user_id = ?')
    .get(remediationId, userId) as Record<string, unknown> | undefined;

  if (!row) {
    throw new RemediationError('Remediation proposal not found.', 404);
  }
  return mapRow(row);
}

export function approveAndApplyRemediation(
  remediationId: string,
  userId: string
): RemediationProposal {
  const db = getDb();
  const proposal = getOwnedRemediation(remediationId, userId);

  if (proposal.status === 'rejected') {
    throw new RemediationError('Cannot approve a proposal that was already rejected.', 400);
  }

  const sourceDir = getProjectSourceDir(userId, proposal.projectId);
  const backupDir = getProjectBackupDir(userId, proposal.projectId);
  const absTarget = assertPathInsideRoot(sourceDir, proposal.filePath);

  if (!fs.existsSync(absTarget)) {
    throw new RemediationError(`Target file "${proposal.filePath}" not found in project workspace.`, 404);
  }

  // Create immutable snapshot backup before applying changes
  fs.mkdirSync(backupDir, { recursive: true });
  const safeFlatName = proposal.filePath.replace(/[/\\]/g, '__');
  const backupFileName = `${Date.now()}_${proposal.id.slice(0, 8)}_${safeFlatName}.bak`;
  const absBackup = path.join(backupDir, backupFileName);
  const currentDiskContent = fs.readFileSync(absTarget, 'utf8');
  fs.writeFileSync(absBackup, currentDiskContent, 'utf8');

  // Apply approved proposed code safely
  fs.writeFileSync(absTarget, proposal.proposedCode, 'utf8');

  // Update project file sha256 & byte size metadata
  const newBytes = Buffer.byteLength(proposal.proposedCode, 'utf8');
  const newHash = crypto.createHash('sha256').update(proposal.proposedCode, 'utf8').digest('hex');
  const now = new Date().toISOString();

  const tx = db.transaction(() => {
    db.prepare(
      `UPDATE remediation_proposals
       SET status = 'applied', backup_path = ?, reviewed_at = ?
       WHERE id = ? AND user_id = ?`
    ).run(backupFileName, now, proposal.id, userId);

    db.prepare(
      `UPDATE findings SET remediation_status = 'approved' WHERE id = ? AND user_id = ?`
    ).run(proposal.findingId, userId);

    db.prepare(
      `UPDATE project_files SET size_bytes = ?, sha256 = ? WHERE project_id = ? AND relative_path = ?`
    ).run(newBytes, newHash, proposal.projectId, proposal.filePath);

    db.prepare(
      `INSERT INTO remediation_history (id, remediation_id, finding_id, user_id, action, details_json, created_at)
       VALUES (?, ?, ?, ?, 'applied', ?, ?)`
    ).run(
      crypto.randomUUID(),
      proposal.id,
      proposal.findingId,
      userId,
      JSON.stringify({ backupFileName, filePath: proposal.filePath }),
      now
    );
  });

  tx();
  return getOwnedRemediation(proposal.id, userId);
}

export function rejectRemediation(
  remediationId: string,
  userId: string,
  reason?: string
): RemediationProposal {
  const db = getDb();
  const proposal = getOwnedRemediation(remediationId, userId);

  if (proposal.status === 'applied') {
    throw new RemediationError('Proposal has already been applied. Restore backup instead.', 400);
  }

  const now = new Date().toISOString();
  const tx = db.transaction(() => {
    db.prepare(
      `UPDATE remediation_proposals SET status = 'rejected', reviewed_at = ? WHERE id = ? AND user_id = ?`
    ).run(now, proposal.id, userId);

    db.prepare(
      `UPDATE findings SET remediation_status = 'open' WHERE id = ? AND user_id = ? AND remediation_status = 'in_review'`
    ).run(proposal.findingId, userId);

    db.prepare(
      `INSERT INTO remediation_history (id, remediation_id, finding_id, user_id, action, details_json, created_at)
       VALUES (?, ?, ?, ?, 'rejected', ?, ?)`
    ).run(
      crypto.randomUUID(),
      proposal.id,
      proposal.findingId,
      userId,
      JSON.stringify({ reason: reason || 'Rejected by student' }),
      now
    );
  });

  tx();
  return getOwnedRemediation(proposal.id, userId);
}

export async function validateRemediationFix(
  remediationId: string,
  userId: string
): Promise<{
  proposal: RemediationProposal;
  validationScanId: string | null;
  originalRemains: boolean;
  newIssuesCount: number;
}> {
  const db = getDb();
  const proposal = getOwnedRemediation(remediationId, userId);

  if (proposal.status !== 'applied' && proposal.status !== 'approved') {
    throw new RemediationError('Approve and apply the proposed fix before running static validation.', 400);
  }

  const originalFinding = db
    .prepare('SELECT * FROM findings WHERE id = ? AND user_id = ?')
    .get(proposal.findingId, userId) as Record<string, unknown> | undefined;

  if (!originalFinding) {
    throw new RemediationError('Original finding record not found.', 404);
  }

  const origRuleId = String(originalFinding.rule_id);
  const origScanner = String(originalFinding.scanner_name);
  const origCategory = String(originalFinding.category);
  const origScanId = String(originalFinding.scan_id);

  const sourceDir = getProjectSourceDir(userId, proposal.projectId);
  const scannersToRun = origScanner === 'custom' ? ['custom', 'eslint'] : ['custom', origScanner, 'eslint'];
  const uniqueScanners = Array.from(new Set(scannersToRun));

  const revalidationScan = await executeProjectScan({
    userId,
    projectId: proposal.projectId,
    sourcePath: sourceDir,
    scanners: uniqueScanners,
    triggerType: 'revalidation',
  });

  const scannerUsedOk = (revalidationScan.scannerResults || []).some(
    (sr) => sr.scannerName === origScanner && sr.status === 'completed'
  );

  // Compare original findings on this file vs new findings on this file
  const prevFileFindings = db
    .prepare(
      `SELECT rule_id, category, start_line FROM findings
       WHERE scan_id = ? AND file_path = ?`
    )
    .all(origScanId, proposal.filePath) as Array<{ rule_id: string; category: string; start_line: number }>;

  const newFileFindings = db
    .prepare(
      `SELECT rule_id, category, start_line, title, severity FROM findings
       WHERE scan_id = ? AND file_path = ?`
    )
    .all(revalidationScan.id, proposal.filePath) as Array<{
    rule_id: string;
    category: string;
    start_line: number;
    title: string;
    severity: string;
  }>;

  const originalRemains = newFileFindings.some(
    (nf) => nf.rule_id === origRuleId || nf.category === origCategory
  );

  const prevRuleSet = new Set(prevFileFindings.map((pf) => `${pf.rule_id}::${pf.category}`));
  const newlyIntroduced = newFileFindings.filter(
    (nf) => !prevRuleSet.has(`${nf.rule_id}::${nf.category}`)
  );

  let validationStatus: ValidationStatus;
  let validationSummary: string;

  if (!scannerUsedOk && origScanner !== 'custom') {
    validationStatus = 'validation_unavailable';
    validationSummary = `Original scanner (${origScanner}) is unavailable in this environment to confirm resolution.`;
  } else if (originalRemains && newlyIntroduced.length > 0) {
    validationStatus = 'new_issues_detected';
    validationSummary = `Original vulnerability (${origRuleId}) still detected on ${proposal.filePath}, and ${newlyIntroduced.length} new finding(s) appeared.`;
  } else if (originalRemains) {
    validationStatus = 'not_resolved';
    validationSummary = `Rescan still detected ${origRuleId} (${origCategory}) in ${proposal.filePath}. Manual review required.`;
  } else if (newlyIntroduced.length > 0) {
    validationStatus = 'new_issues_detected';
    validationSummary = `Original vulnerability (${origRuleId}) no longer detected, but ${newlyIntroduced.length} new finding(s) appeared in ${proposal.filePath}.`;
  } else {
    validationStatus = 'validated';
    validationSummary = `Static rescan (${uniqueScanners.join(', ')}) confirmed ${origRuleId} is no longer detected in ${proposal.filePath} with zero new findings introduced.`;
  }

  const validatedAt = new Date().toISOString();

  const tx = db.transaction(() => {
    db.prepare(
      `UPDATE remediation_proposals
       SET validation_status = ?, validation_summary = ?, validated_at = ?
       WHERE id = ? AND user_id = ?`
    ).run(validationStatus, validationSummary, validatedAt, proposal.id, userId);

    if (validationStatus === 'validated') {
      db.prepare(
        `UPDATE findings SET remediation_status = 'remediated' WHERE id = ? AND user_id = ?`
      ).run(proposal.findingId, userId);
    }

    db.prepare(
      `INSERT INTO remediation_history (id, remediation_id, finding_id, user_id, action, details_json, created_at)
       VALUES (?, ?, ?, ?, 'validated', ?, ?)`
    ).run(
      crypto.randomUUID(),
      proposal.id,
      proposal.findingId,
      userId,
      JSON.stringify({
        validationScanId: revalidationScan.id,
        validationStatus,
        originalRemains,
        newIssuesCount: newlyIntroduced.length,
      }),
      validatedAt
    );
  });

  tx();

  return {
    proposal: getOwnedRemediation(proposal.id, userId),
    validationScanId: revalidationScan.id,
    originalRemains,
    newIssuesCount: newlyIntroduced.length,
  };
}
