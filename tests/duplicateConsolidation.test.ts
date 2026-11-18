import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../server.ts';
import { closeDb, getDb, initDatabase } from '../server/database/db.ts';
import { parseBanditOutput } from '../server/scanners/adapters/banditAdapter.ts';
import { parseSemgrepOutput } from '../server/scanners/adapters/semgrepAdapter.ts';
import {
  deduplicateDiagnostics,
  deduplicateFindings,
  normalizeFinding,
  type NormalizedFinding,
  type RawScanDiagnostic,
} from '../server/scanners/normalization/normalizer.ts';

let tmpDir: string;
let server: http.Server;
let baseUrl: string;
const createdUserDirs: string[] = [];

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-dedupe-'));
  process.env.DATABASE_PATH = path.join(tmpDir, 'dedupe.db');
  const app = createApp();
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  closeDb();
  delete process.env.DATABASE_PATH;
  fs.rmSync(tmpDir, { recursive: true, force: true });
  for (const dir of createdUserDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

async function registerStudent(fullName: string, email: string) {
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fullName,
      email,
      password: 'Password123!',
      confirmPassword: 'Password123!',
    }),
  });
  expect(res.status).toBe(201);
  const cookie = res.headers.get('set-cookie')?.split(';')[0] || '';
  const body = (await res.json()) as { user: { id: string }; csrfToken: string };
  createdUserDirs.push(
    path.join(process.cwd(), 'data', 'projects', body.user.id.replace(/[^a-zA-Z0-9_-]/g, ''))
  );
  return { user: body.user, cookie, csrfToken: body.csrfToken };
}

describe('Duplicate Findings & Diagnostics Consolidation', () => {
  it('transitively consolidates multi-scanner findings across line offsets regardless of input order', () => {
    const fBandit12 = normalizeFinding(
      {
        scannerName: 'bandit',
        detectionSource: 'confirmed_tool',
        ruleId: 'B608',
        title: 'Possible SQL injection vector through string-based query construction',
        description: 'Bandit B608 on line 12',
        category: 'SQL Injection',
        severity: 'Medium',
        confidence: 'Medium',
        cweId: 'CWE-89',
        filePath: 'vulnerable.py',
        startLine: 12,
        endLine: 12,
        language: 'Python',
      },
      'proj-x'
    );
    const fCustom12_13 = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-PY-SQLI',
        title: 'SQL Injection via dynamic query concatenation',
        description: 'Custom AST SQLi across lines 12-13',
        category: 'SQL Injection',
        severity: 'Critical',
        confidence: 'High',
        cweId: 'CWE-89',
        filePath: 'vulnerable.py',
        startLine: 12,
        endLine: 13,
        language: 'Python',
      },
      'proj-x'
    );
    const fSemgrep13 = normalizeFinding(
      {
        scannerName: 'semgrep',
        detectionSource: 'confirmed_tool',
        ruleId: 'python.lang.security.audit.formatted-sql-query',
        title: 'Formatted SQL query',
        description: 'Semgrep detected formatted SQL execution',
        category: 'security', // Generic category emitted by some Semgrep rulesets
        severity: 'High',
        confidence: 'High',
        cweId: null,
        filePath: './vulnerable.py',
        startLine: 13,
        endLine: 13,
        language: 'Python',
      },
      'proj-x'
    );
    const fSqli40 = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-PY-SQLI',
        title: 'SQL Injection on line 40',
        description: 'Direct SQLi on line 40',
        category: 'SQL Injection',
        severity: 'Critical',
        confidence: 'High',
        cweId: 'CWE-89',
        filePath: 'vulnerable.py',
        startLine: 40,
        endLine: 40,
        language: 'Python',
      },
      'proj-x'
    );
    const fSecret47Gitleaks = normalizeFinding(
      {
        scannerName: 'gitleaks',
        detectionSource: 'confirmed_tool',
        ruleId: 'generic-api-key',
        title: 'Exposed secret credential',
        description: 'Gitleaks detected hardcoded credential',
        category: 'Exposed Secrets',
        severity: 'High',
        confidence: 'High',
        cweId: 'CWE-798',
        filePath: 'vulnerable.py',
        startLine: 47,
        endLine: 47,
        language: 'Python',
      },
      'proj-x'
    );
    const fSecret47Custom = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-HARDCODED-SECRET',
        title: 'Hardcoded API secret',
        description: 'Custom detected hardcoded credential',
        category: 'Hardcoded Credentials',
        severity: 'High',
        confidence: 'High',
        cweId: 'CWE-798',
        filePath: 'vulnerable.py',
        startLine: 47,
        endLine: 47,
        language: 'Python',
      },
      'proj-x'
    );

    // Deliberately put Semgrep line 13 BEFORE Bandit line 12 and Custom 12-13
    const ordered1: NormalizedFinding[] = [
      fSemgrep13,
      fSqli40,
      fSecret47Gitleaks,
      fBandit12,
      fCustom12_13,
      fSecret47Custom,
    ];
    const ordered2: NormalizedFinding[] = [...ordered1].reverse();

    const deduped1 = deduplicateFindings(ordered1);
    const deduped2 = deduplicateFindings(ordered2);

    expect(deduped1).toHaveLength(3);
    expect(deduped2).toHaveLength(3);
    expect(deduped1.map((f) => f.canonicalKey)).toEqual(deduped2.map((f) => f.canonicalKey));

    const sqli12 = deduped1.find((f) => f.startLine === 12);
    expect(sqli12).toBeDefined();
    expect(sqli12!.endLine).toBe(13);
    expect(sqli12!.contributingScanners).toEqual(['bandit', 'custom', 'semgrep']);
    expect(sqli12!.scannerEvidence).toHaveLength(3);
    expect(sqli12!.severity).toBe('Critical');

    const sqli40 = deduped1.find((f) => f.startLine === 40);
    expect(sqli40).toBeDefined();

    const secret47 = deduped1.find((f) => f.startLine === 47);
    expect(secret47).toBeDefined();
    expect(secret47!.contributingScanners).toEqual(['custom', 'gitleaks']);
  });

  it('consolidates Bandit B404 subprocess import without polluting Command Injection', () => {
    const banditJson = JSON.stringify({
      results: [
        {
          test_id: 'B404',
          test_name: 'blacklist',
          issue_severity: 'LOW',
          issue_confidence: 'HIGH',
          issue_text: 'Consider possible security implications associated with the subprocess module.',
          filename: 'vulnerable.py',
          line_number: 3,
          end_col_offset: 17,
          col_offset: 0,
        },
      ],
      errors: [],
    });

    const parsed = parseBanditOutput(banditJson, '/tmp/ws');
    expect(parsed).toHaveLength(1);
    expect(parsed[0].category).toBe('Security Misconfiguration');
    expect(parsed[0].category).not.toBe('Command Injection');
  });

  it('deduplicates cross-scanner syntax diagnostics including unlocated Bandit AST errors', () => {
    const raw: RawScanDiagnostic[] = [
      {
        scannerName: 'bandit',
        filePath: 'vulnerable.py',
        line: 1,
        unlocated: true,
        severity: 'error',
        kind: 'syntax_error',
        message: 'syntax error while parsing AST from file',
      },
      {
        scannerName: 'custom',
        filePath: './vulnerable.py',
        line: 66,
        column: 10,
        severity: 'error',
        kind: 'syntax_error',
        message: "Unclosed '(' on line 66.",
      },
      {
        scannerName: 'semgrep',
        filePath: 'vulnerable.py',
        line: 67,
        column: 5,
        severity: 'error',
        kind: 'syntax_error',
        message: 'Syntax error near return statement',
      },
    ];

    const deduped = deduplicateDiagnostics(raw);
    expect(deduped).toHaveLength(1);
    expect(deduped[0].line).toBe(66);
    expect(deduped[0].column).toBe(10);
    expect(deduped[0].contributingScanners).toEqual(['bandit', 'custom', 'semgrep']);
    expect(deduped[0].scannerMessages).toHaveLength(3);
  });

  it('prevents cross-scan finding multiplication in GET /api/findings and GET /api/dashboard/stats', async () => {
    const student = await registerStudent('Alice', 'alice-dedupe@cse.edu');

    const projRes = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: student.cookie,
        'X-CSRF-Token': student.csrfToken,
      },
      body: JSON.stringify({ name: 'Multi-Scan App', description: 'Check latest scan scoping' }),
    });
    const { project } = (await projRes.json()) as { project: { id: string } };

    const pyCode = [
      'import sqlite3',
      'def q(cursor, uid):',
      '    cursor.execute("SELECT * FROM users WHERE id = " + uid)',
      '',
    ].join('\n');

    const form = new FormData();
    form.append('files', new Blob([pyCode], { type: 'text/x-python' }), 'app.py');
    const upRes = await fetch(`${baseUrl}/api/projects/${project.id}/upload`, {
      method: 'POST',
      headers: { Cookie: student.cookie, 'X-CSRF-Token': student.csrfToken },
      body: form,
    });
    expect(upRes.status).toBe(200);

    // Run Scan 1
    const s1Res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: student.cookie,
        'X-CSRF-Token': student.csrfToken,
      },
      body: JSON.stringify({ projectId: project.id, scanners: ['custom'] }),
    });
    expect(s1Res.status).toBe(201);
    const { scan: scan1 } = (await s1Res.json()) as { scan: { id: string; totalFindings: number } };

    // Run Scan 2 (rescan without modifying code)
    const s2Res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: student.cookie,
        'X-CSRF-Token': student.csrfToken,
      },
      body: JSON.stringify({ projectId: project.id, scanners: ['custom'] }),
    });
    expect(s2Res.status).toBe(201);
    const { scan: scan2 } = (await s2Res.json()) as { scan: { id: string; totalFindings: number } };

    expect(scan1.totalFindings).toBe(scan2.totalFindings);

    // Default GET /api/findings returns ONLY latest scan's findings (not 2x!)
    const fRes = await fetch(`${baseUrl}/api/findings?projectId=${project.id}`, {
      headers: { Cookie: student.cookie },
    });
    expect(fRes.status).toBe(200);
    const fBody = (await fRes.json()) as {
      findings: Array<{ scanId: string }>;
      summary: { totalFindings: number };
    };
    expect(fBody.findings).toHaveLength(scan2.totalFindings);
    expect(fBody.summary.totalFindings).toBe(scan2.totalFindings);
    expect(fBody.findings.every((f) => f.scanId === scan2.id)).toBe(true);

    // Dashboard stats also reflects latest scan count only (never 2x)
    const dRes = await fetch(`${baseUrl}/api/dashboard/stats`, {
      headers: { Cookie: student.cookie },
    });
    const dBody = (await dRes.json()) as { stats: { totalVulnerabilities: number; totalScans: number } };
    expect(dBody.stats.totalVulnerabilities).toBe(scan2.totalFindings);
    expect(dBody.stats.totalScans).toBe(2);

    // Historical scan can still be queried explicitly via ?scanId=scan1.id
    const histRes = await fetch(`${baseUrl}/api/findings?scanId=${scan1.id}`, {
      headers: { Cookie: student.cookie },
    });
    const histBody = (await histRes.json()) as { findings: Array<{ scanId: string }> };
    expect(histBody.findings).toHaveLength(scan1.totalFindings);
    expect(histBody.findings.every((f) => f.scanId === scan1.id)).toBe(true);
  });

  it('safely backs up a pre-v3 SQLite database, consolidates existing duplicates, and preserves AI/remediation links', () => {
    closeDb();
    const legacyDbPath = path.join(tmpDir, 'legacy-pre-v3.db');
    const rawDb = new Database(legacyDbPath);

    // Build pre-v3 schema (v1 + v2) with existing duplicate findings in one scan
    rawDb.exec(`
      CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);
      INSERT INTO schema_migrations VALUES (1, 'initial_securelens_schema', '2026-01-01T00:00:00.000Z');
      INSERT INTO schema_migrations VALUES (2, 'scan_snapshots_diagnostics_and_evidence_separation', '2026-01-01T00:00:00.000Z');
      CREATE TABLE users (id TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, preferred_model TEXT NOT NULL DEFAULT 'gemini-2.5-flash', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, user_agent TEXT, ip_address TEXT);
      CREATE TABLE projects (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', primary_language TEXT, languages_json TEXT NOT NULL DEFAULT '[]', source_path TEXT NOT NULL, file_count INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE project_files (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, relative_path TEXT NOT NULL, language TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, is_supported INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
      CREATE TABLE scan_sessions (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL, trigger_type TEXT NOT NULL DEFAULT 'manual', scanners_requested_json TEXT NOT NULL DEFAULT '[]', total_findings INTEGER NOT NULL DEFAULT 0, critical_count INTEGER NOT NULL DEFAULT 0, high_count INTEGER NOT NULL DEFAULT 0, medium_count INTEGER NOT NULL DEFAULT 0, low_count INTEGER NOT NULL DEFAULT 0, info_count INTEGER NOT NULL DEFAULT 0, started_at TEXT NOT NULL, completed_at TEXT, error_message TEXT);
      CREATE TABLE scanner_configurations (name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1, timeout_ms INTEGER NOT NULL DEFAULT 30000, updated_at TEXT NOT NULL);
      CREATE TABLE scanner_results (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, scanner_name TEXT NOT NULL, available INTEGER NOT NULL, version TEXT, status TEXT NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0, findings_count INTEGER NOT NULL DEFAULT 0, error_message TEXT, install_hint TEXT, executed_at TEXT NOT NULL);
      CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, project_id TEXT NOT NULL, user_id TEXT NOT NULL, fingerprint TEXT NOT NULL, scanner_name TEXT NOT NULL, detection_source TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, cwe_id TEXT, owasp_category TEXT, file_path TEXT NOT NULL, start_line INTEGER NOT NULL DEFAULT 1, end_line INTEGER NOT NULL DEFAULT 1, start_col INTEGER, end_col INTEGER, language TEXT NOT NULL, code_snippet TEXT NOT NULL DEFAULT '', redacted_evidence TEXT, recommendation TEXT NOT NULL DEFAULT '', references_json TEXT NOT NULL DEFAULT '[]', contributing_scanners_json TEXT NOT NULL DEFAULT '[]', scanner_evidence_json TEXT NOT NULL DEFAULT '[]', remediation_status TEXT NOT NULL DEFAULT 'open', detected_at TEXT NOT NULL);
      CREATE TABLE ai_analyses (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, user_id TEXT NOT NULL, model_name TEXT NOT NULL, vulnerability_meaning TEXT NOT NULL, why_unsafe TEXT NOT NULL, exploitation_scenario TEXT NOT NULL, real_world_impact TEXT NOT NULL, risk_context TEXT NOT NULL, secure_recommendation TEXT NOT NULL, cwe_owasp_context TEXT NOT NULL, corrected_code_example TEXT NOT NULL, false_positive_assessment TEXT NOT NULL, false_positive_reasoning TEXT NOT NULL, uncertainty_note TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE ai_conversations (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, project_id TEXT, title TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE ai_messages (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, model_name TEXT, created_at TEXT NOT NULL);
      CREATE TABLE remediation_proposals (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, project_id TEXT NOT NULL, user_id TEXT NOT NULL, file_path TEXT NOT NULL, original_code TEXT NOT NULL, proposed_code TEXT NOT NULL, diff_summary TEXT NOT NULL, explanation TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', validation_status TEXT NOT NULL DEFAULT 'pending', validation_summary TEXT, backup_path TEXT, created_at TEXT NOT NULL, reviewed_at TEXT, validated_at TEXT);
      CREATE TABLE remediation_history (id TEXT PRIMARY KEY, remediation_id TEXT NOT NULL, finding_id TEXT NOT NULL, user_id TEXT NOT NULL, action TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
      CREATE TABLE reports (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, project_id TEXT NOT NULL, scan_id TEXT, title TEXT NOT NULL, format TEXT NOT NULL, file_path TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
      CREATE TABLE learning_progress (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, topic_slug TEXT NOT NULL, quiz_score INTEGER NOT NULL DEFAULT 0, quiz_total INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);
      CREATE TABLE scan_file_snapshots (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, project_id TEXT NOT NULL, user_id TEXT NOT NULL, file_path TEXT NOT NULL, language TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0, content TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE scan_diagnostics (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, project_id TEXT NOT NULL, user_id TEXT NOT NULL, scanner_name TEXT NOT NULL, file_path TEXT NOT NULL, line INTEGER NOT NULL DEFAULT 1, column_num INTEGER, severity TEXT NOT NULL DEFAULT 'error', kind TEXT NOT NULL DEFAULT 'syntax_error', message TEXT NOT NULL, created_at TEXT NOT NULL);

      INSERT INTO users VALUES ('u1', 'Test Student', 'test@cse.edu', 'hash', 'gemini-2.5-flash', '2026-01-01', '2026-01-01');
      INSERT INTO projects VALUES ('p1', 'u1', 'Legacy Project', '', 'Python', '["Python"]', '/tmp/p1', 1, 100, '2026-01-01', '2026-01-01');
      INSERT INTO scan_sessions (id, project_id, user_id, status, trigger_type, scanners_requested_json, total_findings, critical_count, high_count, medium_count, low_count, info_count, started_at, completed_at, error_message)
      VALUES ('s1', 'p1', 'u1', 'completed', 'manual', '["custom","bandit"]', 2, 1, 0, 1, 0, 0, '2026-01-01', '2026-01-01', NULL);

      INSERT INTO findings VALUES ('f1', 's1', 'p1', 'u1', 'fp1', 'custom', 'confirmed_tool', 'CUSTOM-PY-SQLI', 'SQLi', 'Custom desc', 'SQL Injection', 'Critical', 'High', 'CWE-89', 'A03:2021', 'app.py', 12, 13, 4, 30, 'Python', 'cursor.execute(q)', NULL, 'Use ? params', '[]', '["custom"]', '[]', 'open', '2026-01-01');
      INSERT INTO findings VALUES ('f2', 's1', 'p1', 'u1', 'fp2', 'bandit', 'confirmed_tool', 'B608', 'Bandit SQLi', 'Bandit desc', 'SQL Injection', 'Medium', 'Medium', 'CWE-89', 'A03:2021', 'app.py', 12, 12, NULL, NULL, 'Python', 'cursor.execute(q)', NULL, 'Use ? params', '[]', '["bandit"]', '[]', 'open', '2026-01-01');
      INSERT INTO ai_analyses VALUES ('ai1', 'f2', 'u1', 'gemini', 'Meaning', 'Unsafe', 'Exploit', 'Impact', 'Risk', 'Rec', 'CWE-89', 'fixed', 'likely_genuine', 'reason', 'note', '2026-01-01');
      INSERT INTO remediation_proposals VALUES ('rem1', 'f2', 'p1', 'u1', 'app.py', 'old', 'new', 'diff', 'exp', 'pending', 'pending', NULL, NULL, '2026-01-01', NULL, NULL);
      INSERT INTO scan_diagnostics VALUES ('d1', 's1', 'p1', 'u1', 'custom', 'app.py', 66, 10, 'error', 'syntax_error', 'Unclosed paren', '2026-01-01');
      INSERT INTO scan_diagnostics VALUES ('d2', 's1', 'p1', 'u1', 'bandit', 'app.py', 1, NULL, 'error', 'syntax_error', 'syntax error while parsing AST', '2026-01-01');
    `);
    rawDb.close();

    // Run v3 initialization against legacy DB
    const migratedDb = initDatabase(legacyDbPath);

    // 1. Pre-v3 backup verified
    const backupPath = `${legacyDbPath}.pre-v3.bak`;
    expect(fs.existsSync(backupPath)).toBe(true);
    expect(fs.statSync(backupPath).size).toBeGreaterThan(0);

    // 2. Duplicate findings consolidated from 2 -> 1 while preserving AI & remediation on survivor
    const survivingFindings = migratedDb
      .prepare('SELECT * FROM findings WHERE scan_id = ?')
      .all('s1') as Array<{
      id: string;
      severity: string;
      contributing_scanners_json: string;
      canonical_key: string;
    }>;
    expect(survivingFindings).toHaveLength(1);
    expect(survivingFindings[0].severity).toBe('Critical');
    expect(JSON.parse(survivingFindings[0].contributing_scanners_json)).toEqual(['bandit', 'custom']);

    const aiRow = migratedDb.prepare('SELECT finding_id FROM ai_analyses WHERE id = ?').get('ai1') as {
      finding_id: string;
    };
    const remRow = migratedDb.prepare('SELECT finding_id FROM remediation_proposals WHERE id = ?').get('rem1') as {
      finding_id: string;
    };
    expect(aiRow.finding_id).toBe(survivingFindings[0].id);
    expect(remRow.finding_id).toBe(survivingFindings[0].id);

    // 3. Scan session totals recomputed accurately
    const scanRow = migratedDb
      .prepare('SELECT total_findings, critical_count, medium_count FROM scan_sessions WHERE id = ?')
      .get('s1') as { total_findings: number; critical_count: number; medium_count: number };
    expect(scanRow.total_findings).toBe(1);
    expect(scanRow.critical_count).toBe(1);
    expect(scanRow.medium_count).toBe(0);

    // 4. Diagnostics consolidated to 1
    const diags = migratedDb.prepare('SELECT * FROM scan_diagnostics WHERE scan_id = ?').all('s1') as Array<{
      line: number;
      contributing_scanners_json: string;
    }>;
    expect(diags).toHaveLength(1);
    expect(diags[0].line).toBe(66);
    expect(JSON.parse(diags[0].contributing_scanners_json)).toEqual(['bandit', 'custom']);

    // 5. Unique DB index prevents duplicate (scan_id, canonical_key) insertion
    expect(() =>
      migratedDb
        .prepare(
          `INSERT INTO findings (id, scan_id, project_id, user_id, fingerprint, canonical_key, scanner_name, detection_source, rule_id, title, description, category, severity, confidence, file_path, language, detected_at)
           VALUES ('f-dup', 's1', 'p1', 'u1', 'fp', ?, 'semgrep', 'confirmed_tool', 'r1', 't', 'd', 'SQL Injection', 'High', 'High', 'app.py', 'Python', '2026-01-01')`
        )
        .run(survivingFindings[0].canonical_key)
    ).toThrow(/UNIQUE constraint failed/i);

    // Verify parseSemgrepOutput still returns line 40 SQLi cleanly
    const tmpWs = fs.mkdtempSync(path.join(tmpDir, 'sg-'));
    fs.writeFileSync(path.join(tmpWs, 'app.py'), 'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n', 'utf8');
    const sg = parseSemgrepOutput(
      JSON.stringify({
        results: [
          {
            check_id: 'python.lang.security.audit.formatted-sql-query',
            path: 'app.py',
            start: { line: 1, col: 1 },
            end: { line: 1, col: 40 },
            extra: { message: 'Formatted SQL', severity: 'ERROR', lines: 'requires login' },
          },
        ],
      }),
      tmpWs
    );
    expect(sg[0].codeSnippet).not.toMatch(/requires login/i);
  });
});
