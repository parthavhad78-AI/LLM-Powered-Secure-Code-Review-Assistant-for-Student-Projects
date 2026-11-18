import type Database from 'better-sqlite3';
import {
  computeFindingCanonicalKey,
  deduplicateDiagnostics,
  getCanonicalFamily,
  type RawScanDiagnostic,
} from '../scanners/normalization/normalizer.ts';

interface Migration {
  version: number;
  name: string;
  sql: string;
}

const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'initial_securelens_schema',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        preferred_model TEXT NOT NULL DEFAULT 'gemini-4-hydrogen',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        user_agent TEXT,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        primary_language TEXT,
        languages_json TEXT NOT NULL DEFAULT '[]',
        source_path TEXT NOT NULL,
        file_count INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS project_files (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        relative_path TEXT NOT NULL,
        language TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        is_supported INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        UNIQUE(project_id, relative_path)
      );

      CREATE TABLE IF NOT EXISTS scan_sessions (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        status TEXT NOT NULL,
        trigger_type TEXT NOT NULL DEFAULT 'manual',
        scanners_requested_json TEXT NOT NULL DEFAULT '[]',
        total_findings INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        medium_count INTEGER NOT NULL DEFAULT 0,
        low_count INTEGER NOT NULL DEFAULT 0,
        info_count INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        error_message TEXT,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS scanner_configurations (
        name TEXT PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1,
        timeout_ms INTEGER NOT NULL DEFAULT 30000,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS scanner_results (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        scanner_name TEXT NOT NULL,
        available INTEGER NOT NULL,
        version TEXT,
        status TEXT NOT NULL,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        findings_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        install_hint TEXT,
        executed_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        scanner_name TEXT NOT NULL,
        detection_source TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        cwe_id TEXT,
        owasp_category TEXT,
        file_path TEXT NOT NULL,
        start_line INTEGER NOT NULL DEFAULT 1,
        end_line INTEGER NOT NULL DEFAULT 1,
        language TEXT NOT NULL,
        code_snippet TEXT NOT NULL DEFAULT '',
        redacted_evidence TEXT,
        recommendation TEXT NOT NULL DEFAULT '',
        references_json TEXT NOT NULL DEFAULT '[]',
        remediation_status TEXT NOT NULL DEFAULT 'open',
        detected_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS ai_analyses (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        model_name TEXT NOT NULL,
        vulnerability_meaning TEXT NOT NULL,
        why_unsafe TEXT NOT NULL,
        exploitation_scenario TEXT NOT NULL,
        real_world_impact TEXT NOT NULL,
        risk_context TEXT NOT NULL,
        secure_recommendation TEXT NOT NULL,
        cwe_owasp_context TEXT NOT NULL,
        corrected_code_example TEXT NOT NULL,
        false_positive_assessment TEXT NOT NULL,
        false_positive_reasoning TEXT NOT NULL,
        uncertainty_note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS ai_conversations (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        project_id TEXT,
        title TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS ai_messages (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        model_name TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (conversation_id) REFERENCES ai_conversations(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS remediation_proposals (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        original_code TEXT NOT NULL,
        proposed_code TEXT NOT NULL,
        diff_summary TEXT NOT NULL,
        explanation TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        validation_status TEXT NOT NULL DEFAULT 'pending',
        validation_summary TEXT,
        backup_path TEXT,
        created_at TEXT NOT NULL,
        reviewed_at TEXT,
        validated_at TEXT,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS remediation_history (
        id TEXT PRIMARY KEY,
        remediation_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY (remediation_id) REFERENCES remediation_proposals(id) ON DELETE CASCADE,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        scan_id TEXT,
        title TEXT NOT NULL,
        format TEXT NOT NULL,
        file_path TEXT NOT NULL,
        summary_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS learning_progress (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        topic_slug TEXT NOT NULL,
        quiz_score INTEGER NOT NULL DEFAULT 0,
        quiz_total INTEGER NOT NULL DEFAULT 0,
        completed INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, topic_slug)
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);
      CREATE INDEX IF NOT EXISTS idx_project_files_project ON project_files(project_id);
      CREATE INDEX IF NOT EXISTS idx_scan_sessions_project ON scan_sessions(project_id);
      CREATE INDEX IF NOT EXISTS idx_scan_sessions_user ON scan_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_scanner_results_scan ON scanner_results(scan_id);
      CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
      CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
      CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
      CREATE INDEX IF NOT EXISTS idx_ai_analyses_finding ON ai_analyses(finding_id);
      CREATE INDEX IF NOT EXISTS idx_ai_conversations_user ON ai_conversations(user_id);
      CREATE INDEX IF NOT EXISTS idx_ai_messages_conv ON ai_messages(conversation_id);
      CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediation_proposals(finding_id);
      CREATE INDEX IF NOT EXISTS idx_remediation_history_rem ON remediation_history(remediation_id);
      CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
      CREATE INDEX IF NOT EXISTS idx_learning_progress_user ON learning_progress(user_id);
    `,
  },
  {
    version: 2,
    name: 'scan_snapshots_diagnostics_and_evidence_separation',
    sql: `
      CREATE TABLE IF NOT EXISTS scan_file_snapshots (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        language TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(scan_id, file_path)
      );

      CREATE INDEX IF NOT EXISTS idx_scan_snapshots_scan_file ON scan_file_snapshots(scan_id, file_path);
      CREATE INDEX IF NOT EXISTS idx_scan_snapshots_user ON scan_file_snapshots(user_id);

      CREATE TABLE IF NOT EXISTS scan_diagnostics (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        scanner_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line INTEGER NOT NULL DEFAULT 1,
        column_num INTEGER,
        severity TEXT NOT NULL DEFAULT 'error',
        kind TEXT NOT NULL DEFAULT 'syntax_error',
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_scan_diagnostics_scan ON scan_diagnostics(scan_id);
      CREATE INDEX IF NOT EXISTS idx_scan_diagnostics_user ON scan_diagnostics(user_id);
    `,
  },
  {
    version: 3,
    name: 'canonical_dedupe_and_github_integration',
    sql: `
      CREATE TABLE IF NOT EXISTS github_connections (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE,
        github_user_id TEXT NOT NULL,
        github_username TEXT NOT NULL,
        access_token_encrypted TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT '',
        connected_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS github_oauth_states (
        state TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_github_oauth_states_user ON github_oauth_states(user_id);
      CREATE INDEX IF NOT EXISTS idx_github_oauth_states_expires ON github_oauth_states(expires_at);
    `,
  },
];

function ensureTableColumns(
  db: Database.Database,
  table: string,
  additions: Array<{ name: string; def: string }>
): void {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  const existing = new Set(cols.map((c) => c.name));
  for (const col of additions) {
    if (!existing.has(col.name)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${col.name} ${col.def};`);
    }
  }
}

function ensureFindingsExtraColumns(db: Database.Database): void {
  ensureTableColumns(db, 'findings', [
    { name: 'start_col', def: 'INTEGER' },
    { name: 'end_col', def: 'INTEGER' },
    { name: 'contributing_scanners_json', def: "TEXT NOT NULL DEFAULT '[]'" },
    { name: 'scanner_evidence_json', def: "TEXT NOT NULL DEFAULT '[]'" },
  ]);
}

function ensureV3Columns(db: Database.Database): void {
  ensureFindingsExtraColumns(db);
  ensureTableColumns(db, 'projects', [
    { name: 'import_method', def: "TEXT NOT NULL DEFAULT 'upload'" },
    { name: 'github_repo_url', def: 'TEXT' },
    { name: 'github_owner', def: 'TEXT' },
    { name: 'github_repo', def: 'TEXT' },
    { name: 'github_branch', def: 'TEXT' },
    { name: 'github_commit_sha', def: 'TEXT' },
    { name: 'github_is_private', def: 'INTEGER NOT NULL DEFAULT 0' },
    { name: 'last_imported_at', def: 'TEXT' },
  ]);
  ensureTableColumns(db, 'scan_sessions', [
    { name: 'repo_url', def: 'TEXT' },
    { name: 'repo_branch', def: 'TEXT' },
    { name: 'commit_sha', def: 'TEXT' },
  ]);
  ensureTableColumns(db, 'findings', [
    { name: 'canonical_key', def: 'TEXT' },
  ]);
  ensureTableColumns(db, 'scan_diagnostics', [
    { name: 'canonical_key', def: 'TEXT' },
    { name: 'contributing_scanners_json', def: "TEXT NOT NULL DEFAULT '[]'" },
    { name: 'scanner_messages_json', def: "TEXT NOT NULL DEFAULT '[]'" },
  ]);
}

const SEV_RANK: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};

const SOURCE_RANK: Record<string, number> = {
  confirmed_tool: 3,
  dependency_advisory: 3,
  pattern_based: 1,
};

const STATUS_RANK: Record<string, number> = {
  remediated: 5,
  approved: 4,
  in_review: 3,
  accepted_risk: 2,
  false_positive: 2,
  open: 1,
};

interface ExistingFindingRow {
  id: string;
  scan_id: string;
  project_id: string;
  scanner_name: string;
  detection_source: string;
  rule_id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  confidence: string;
  cwe_id: string | null;
  owasp_category: string | null;
  file_path: string;
  start_line: number;
  end_line: number;
  start_col: number | null;
  end_col: number | null;
  references_json: string;
  contributing_scanners_json: string;
  scanner_evidence_json: string;
  remediation_status: string;
  redacted_evidence: string | null;
  code_snippet: string;
  canonical_key: string | null;
}

function areExistingRowsCompatible(a: ExistingFindingRow, b: ExistingFindingRow): boolean {
  const normA = a.file_path.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
  const normB = b.file_path.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
  if (normA !== normB) return false;
  if (Math.max(a.start_line, b.start_line) > Math.min(a.end_line, b.end_line)) return false;

  if (a.category === 'Vulnerable Dependency' || b.category === 'Vulnerable Dependency') {
    return a.category === b.category && a.rule_id === b.rule_id;
  }

  const famA = getCanonicalFamily({
    category: a.category,
    cweId: a.cwe_id,
    ruleId: a.rule_id,
    title: a.title,
  });
  const famB = getCanonicalFamily({
    category: b.category,
    cweId: b.cwe_id,
    ruleId: b.rule_id,
    title: b.title,
  });

  if (famA === 'MISCONFIG' && famB === 'MISCONFIG') {
    if (a.cwe_id && b.cwe_id) return a.cwe_id === b.cwe_id;
    return a.rule_id === b.rule_id;
  }

  return famA === famB || (Boolean(a.cwe_id && b.cwe_id) && a.cwe_id === b.cwe_id);
}

export function consolidatePreExistingDuplicates(db: Database.Database): void {
  const scanRows = db.prepare('SELECT id FROM scan_sessions').all() as Array<{ id: string }>;

  const aiCountStmt = db.prepare('SELECT COUNT(*) AS cnt FROM ai_analyses WHERE finding_id = ?');
  const remCountStmt = db.prepare('SELECT COUNT(*) AS cnt FROM remediation_proposals WHERE finding_id = ?');
  const moveAiStmt = db.prepare('UPDATE ai_analyses SET finding_id = ? WHERE finding_id = ?');
  const moveRemStmt = db.prepare('UPDATE remediation_proposals SET finding_id = ? WHERE finding_id = ?');
  const moveHistStmt = db.prepare('UPDATE remediation_history SET finding_id = ? WHERE finding_id = ?');
  const deleteFindingStmt = db.prepare('DELETE FROM findings WHERE id = ?');
  const updateFindingStmt = db.prepare(
    `UPDATE findings
     SET canonical_key = ?, fingerprint = ?, severity = ?, start_line = ?, end_line = ?,
         start_col = ?, end_col = ?, cwe_id = ?, owasp_category = ?, code_snippet = ?,
         redacted_evidence = ?, references_json = ?, contributing_scanners_json = ?,
         scanner_evidence_json = ?, remediation_status = ?
     WHERE id = ?`
  );
  const updateScanCountsStmt = db.prepare(
    `UPDATE scan_sessions
     SET total_findings = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?
     WHERE id = ?`
  );

  for (const scanRow of scanRows) {
    const rows = db
      .prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY file_path ASC, start_line ASC, detected_at ASC')
      .all(scanRow.id) as ExistingFindingRow[];

    if (rows.length > 0) {
      const clusters: ExistingFindingRow[][] = [];
      for (const row of rows) {
        const match = clusters.find((cluster) =>
          cluster.some((member) => areExistingRowsCompatible(member, row))
        );
        if (match) {
          match.push(row);
        } else {
          clusters.push([row]);
        }
      }

      // Fixed-point transitive merge across clusters
      let mergedAny = true;
      while (mergedAny) {
        mergedAny = false;
        for (let i = 0; i < clusters.length; i++) {
          for (let j = i + 1; j < clusters.length; j++) {
            const overlaps = clusters[i].some((a) =>
              clusters[j].some((b) => areExistingRowsCompatible(a, b))
            );
            if (overlaps) {
              clusters[i].push(...clusters[j]);
              clusters.splice(j, 1);
              mergedAny = true;
              break;
            }
          }
          if (mergedAny) break;
        }
      }

      const finalFindingsForScan: Array<{ severity: string }> = [];

      for (const cluster of clusters) {
        // Pick survivor: prefer rows with AI/remediation records attached, then highest source+severity
        const scored = cluster.map((r) => {
          const aiCnt = Number((aiCountStmt.get(r.id) as { cnt: number }).cnt || 0);
          const remCnt = Number((remCountStmt.get(r.id) as { cnt: number }).cnt || 0);
          const hasChildren = aiCnt + remCnt > 0 ? 1000 : 0;
          const score =
            hasChildren +
            (SOURCE_RANK[r.detection_source] || 0) * 20 +
            (SEV_RANK[r.severity] || 0);
          return { row: r, score };
        });
        scored.sort((a, b) => b.score - a.score);

        const primary = scored[0].row;
        const duplicates = scored.slice(1).map((s) => s.row);

        let highestSeverity = primary.severity;
        let bestStatus = primary.remediation_status;
        let startLine = primary.start_line;
        let endLine = primary.end_line;
        let startCol = primary.start_col;
        let endCol = primary.end_col;
        let cweId = primary.cwe_id;
        let owaspCategory = primary.owasp_category;
        let codeSnippet = primary.code_snippet;
        let redactedEvidence = primary.redacted_evidence;

        const scanners = new Set<string>();
        const refs = new Set<string>();
        const evidenceList: Array<Record<string, unknown>> = [];
        const seenEv = new Set<string>();

        for (const item of cluster) {
          if ((SEV_RANK[item.severity] || 0) > (SEV_RANK[highestSeverity] || 0)) {
            highestSeverity = item.severity;
          }
          if ((STATUS_RANK[item.remediation_status] || 0) > (STATUS_RANK[bestStatus] || 0)) {
            bestStatus = item.remediation_status;
          }
          startLine = Math.min(startLine, item.start_line);
          endLine = Math.max(endLine, item.end_line);
          if ((startCol == null || endCol == null) && item.start_col != null && item.end_col != null) {
            startCol = item.start_col;
            endCol = item.end_col;
          }
          if (!cweId && item.cwe_id) cweId = item.cwe_id;
          if (!owaspCategory && item.owasp_category) owaspCategory = item.owasp_category;
          if (!codeSnippet && item.code_snippet) codeSnippet = item.code_snippet;
          if (!redactedEvidence && item.redacted_evidence) redactedEvidence = item.redacted_evidence;

          try {
            const parsedScanners = JSON.parse(item.contributing_scanners_json || '[]');
            if (Array.isArray(parsedScanners) && parsedScanners.length > 0) {
              parsedScanners.forEach((s) => scanners.add(String(s)));
            } else {
              scanners.add(item.scanner_name);
            }
          } catch {
            scanners.add(item.scanner_name);
          }

          try {
            const parsedRefs = JSON.parse(item.references_json || '[]');
            if (Array.isArray(parsedRefs)) {
              parsedRefs.forEach((rf) => refs.add(String(rf)));
            }
          } catch {
            // ignore
          }

          let parsedEv: Array<Record<string, unknown>> = [];
          try {
            const p = JSON.parse(item.scanner_evidence_json || '[]');
            if (Array.isArray(p) && p.length > 0) {
              parsedEv = p;
            }
          } catch {
            parsedEv = [];
          }
          if (parsedEv.length === 0) {
            parsedEv = [
              {
                scannerName: item.scanner_name,
                ruleId: item.rule_id,
                detectionSource: item.detection_source,
                title: item.title,
                description: item.description,
                severity: item.severity,
                confidence: item.confidence,
                startLine: item.start_line,
                endLine: item.end_line,
                startCol: item.start_col,
                endCol: item.end_col,
                redactedEvidence: item.redacted_evidence,
              },
            ];
          }
          for (const ev of parsedEv) {
            const evKey = `${ev.scannerName}::${ev.ruleId}::${ev.startLine}::${ev.endLine}`;
            if (!seenEv.has(evKey)) {
              seenEv.add(evKey);
              evidenceList.push(ev);
            }
          }
        }

        const canonicalKey = computeFindingCanonicalKey(primary.project_id, {
          filePath: primary.file_path,
          category: primary.category,
          cweId,
          ruleId: primary.rule_id,
          title: primary.title,
          startLine,
          endLine,
        });

        for (const dup of duplicates) {
          moveAiStmt.run(primary.id, dup.id);
          moveRemStmt.run(primary.id, dup.id);
          moveHistStmt.run(primary.id, dup.id);
          deleteFindingStmt.run(dup.id);
        }

        updateFindingStmt.run(
          canonicalKey,
          canonicalKey,
          highestSeverity,
          startLine,
          endLine,
          startCol,
          endCol,
          cweId,
          owaspCategory,
          codeSnippet,
          redactedEvidence,
          JSON.stringify(Array.from(refs)),
          JSON.stringify(Array.from(scanners).sort()),
          JSON.stringify(evidenceList),
          bestStatus,
          primary.id
        );

        finalFindingsForScan.push({ severity: highestSeverity });
      }

      updateScanCountsStmt.run(
        finalFindingsForScan.length,
        finalFindingsForScan.filter((f) => f.severity === 'Critical').length,
        finalFindingsForScan.filter((f) => f.severity === 'High').length,
        finalFindingsForScan.filter((f) => f.severity === 'Medium').length,
        finalFindingsForScan.filter((f) => f.severity === 'Low').length,
        finalFindingsForScan.filter((f) => f.severity === 'Informational').length,
        scanRow.id
      );
    }

    // Consolidate pre-existing scan diagnostics per scan_id
    const diagRows = db
      .prepare('SELECT * FROM scan_diagnostics WHERE scan_id = ? ORDER BY created_at ASC')
      .all(scanRow.id) as Array<{
      id: string;
      scanner_name: string;
      file_path: string;
      line: number;
      column_num: number | null;
      severity: 'error' | 'warning';
      kind: 'syntax_error' | 'parse_warning';
      message: string;
    }>;

    if (diagRows.length > 0) {
      const rawDiags: RawScanDiagnostic[] = diagRows.map((d) => ({
        scannerName: (d.scanner_name as RawScanDiagnostic['scannerName']) || 'custom',
        filePath: d.file_path,
        line: d.line,
        column: d.column_num,
        unlocated: d.scanner_name === 'bandit' && d.line === 1 && !d.column_num && /syntax\s*error|ast|parse/i.test(d.message),
        severity: d.severity,
        kind: d.kind,
        message: d.message,
      }));
      const dedupedDiags = deduplicateDiagnostics(rawDiags);
      const updateDiagStmt = db.prepare(
        `UPDATE scan_diagnostics
         SET canonical_key = ?, scanner_name = ?, contributing_scanners_json = ?, scanner_messages_json = ?,
             file_path = ?, line = ?, column_num = ?, severity = ?, message = ?
         WHERE id = ?`
      );
      const deleteDiagStmt = db.prepare('DELETE FROM scan_diagnostics WHERE id = ?');

      // Keep one existing ID per canonical diagnostic, delete the rest
      const keepIds = new Set<string>();
      dedupedDiags.forEach((norm, idx) => {
        const survivor = diagRows[idx];
        keepIds.add(survivor.id);
        updateDiagStmt.run(
          norm.canonicalKey,
          norm.scannerName,
          JSON.stringify(norm.contributingScanners),
          JSON.stringify(norm.scannerMessages),
          norm.filePath,
          norm.line,
          norm.column,
          norm.severity,
          norm.message,
          survivor.id
        );
      });
      for (const d of diagRows) {
        if (!keepIds.has(d.id)) {
          deleteDiagStmt.run(d.id);
        }
      }
    }
  }
}

export function runMigrations(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  const appliedRows = db
    .prepare('SELECT version FROM schema_migrations')
    .all() as Array<{ version: number }>;
  const applied = new Set(appliedRows.map((r) => r.version));

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;

    const applyTx = db.transaction(() => {
      db.exec(migration.sql);
      if (migration.version === 2) {
        ensureFindingsExtraColumns(db);
      }
      if (migration.version === 3) {
        ensureV3Columns(db);
        consolidatePreExistingDuplicates(db);
        db.exec(`
          CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_canonical
            ON findings(scan_id, canonical_key);
          CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_diagnostics_scan_canonical
            ON scan_diagnostics(scan_id, canonical_key);
        `);
      }
      db.prepare(
        'INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)'
      ).run(migration.version, migration.name, new Date().toISOString());
    });

    applyTx();
  }

  // Defensive check in case DB was restored from an intermediate schema state
  ensureV3Columns(db);

  // Seed default scanner configuration rows safely
  const now = new Date().toISOString();
  const insertCfg = db.prepare(
    `INSERT OR IGNORE INTO scanner_configurations (name, enabled, timeout_ms, updated_at) VALUES (?, 1, 30000, ?)`
  );
  for (const scanner of ['custom', 'bandit', 'semgrep', 'gitleaks', 'eslint', 'osv']) {
    insertCfg.run(scanner, now);
  }
}
