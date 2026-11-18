import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../server.ts';
import { validateAiReferencedLocations, validateAnalysisPayload, validateFixPayload } from '../server/ai/aiService.ts';
import { closeDb, getDb } from '../server/database/db.ts';
import { approveAndApplyRemediation, validateRemediationFix } from '../server/remediation/remediationService.ts';
import { parseBanditOutput } from '../server/scanners/adapters/banditAdapter.ts';
import { parseSemgrepOutput } from '../server/scanners/adapters/semgrepAdapter.ts';
import { getFindingFullSnapshot, getFindingSourceContext } from '../server/scanners/findingGuidance.ts';
import { deduplicateFindings, normalizeFinding } from '../server/scanners/normalization/normalizer.ts';
import { analyzePythonFileWithDiagnostics } from '../server/scanners/rules/customRules.ts';
import { redactTextSecrets } from '../server/scanners/security/secretRedactor.ts';

// Carefully line-indexed vulnerable.py fixture matching all 8 test scenarios + line 66 syntax error
const VULNERABLE_PY_LINES: string[] = [
  'import hashlib',                                                              // 1
  'import sqlite3',                                                              // 2
  'import subprocess',                                                           // 3
  '',                                                                            // 4
  'def get_db():',                                                               // 5
  '    return sqlite3.connect("app.db")',                                        // 6
  '',                                                                            // 7
  'def find_user_by_name(username):',                                            // 8
  '    conn = get_db()',                                                         // 9
  '    cursor = conn.cursor()',                                                  // 10
  '    # Dynamic SQL concatenation across lines 12-13',                          // 11
  '    query = "SELECT * FROM users WHERE username = \'" + username + "\'"',     // 12
  '    cursor.execute(query)',                                                   // 13
  '    return cursor.fetchall()',                                                // 14
  '',                                                                            // 15
  'def hash_user_password(password):',                                           // 16
  '    # Weak password hashing on line 18',                                      // 17
  '    return hashlib.md5(password.encode()).hexdigest()',                       // 18
  '',                                                                            // 19
  'def list_directory(folder_name):',                                            // 20
  '    # Helper setup padding',                                                  // 21
  '    target = folder_name.strip()',                                            // 22
  '    if not target:',                                                          // 23
  '        return ""',                                                           // 24
  '    cmd = f"ls -la {target}"',                                                // 25
  '    options = {"capture": True}',                                             // 26
  '    # Multiline shell=True subprocess on lines 29-30',                        // 27
  '    _unused = options.get("capture")',                                        // 28
  '    result = subprocess.run(',                                                // 29
  '        cmd, shell=True, capture_output=True, text=True)',                    // 30
  '    return result.stdout',                                                    // 31
  '',                                                                            // 32
  'def get_profile(user_id):',                                                   // 33
  '    conn = get_db()',                                                         // 34
  '    cursor = conn.cursor()',                                                  // 35
  '    # Padding lines before line 40 SQLi',                                     // 36
  '    if not user_id:',                                                         // 37
  '        return None',                                                         // 38
  '    # Direct SQL injection on line 40',                                       // 39
  '    cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)',          // 40
  '    return cursor.fetchone()',                                                // 41
  '',                                                                            // 42
  'def create_account(username, password):',                                     // 43
  '    conn = get_db()',                                                         // 44
  '    cursor = conn.cursor()',                                                  // 45
  '    # Hardcoded secret credential on line 47',                                // 46
  '    API_SECRET = "test_secret_credential_9876"',                              // 47
  '    # Plaintext password storage across lines 49-51',                         // 48
  '    cursor.execute(',                                                         // 49
  '        "INSERT INTO accounts (username, password) VALUES (?, ?)",',          // 50
  '        (username, password))',                                               // 51
  '    conn.commit()',                                                           // 52
  '    return API_SECRET',                                                       // 53
  '',                                                                            // 54
  'def log_audit_step(username):',                                               // 55
  '    step = "audit"',                                                          // 56
  '    if not username:',                                                        // 57
  '        return False',                                                        // 58
  '    entry = f"{step}:{username}"',                                            // 59
  '    # Padding before syntax error on line 66',                                // 60
  '    normalized = entry.lower()',                                              // 61
  '    length = len(normalized)',                                                // 62
  '    if length == 0:',                                                         // 63
  '        return False',                                                        // 64
  '    # Intentional syntax error (missing closing parenthesis) on line 66',     // 65
  '    print("Processing user:", username',                                      // 66
  '    return True',                                                             // 67
  '',                                                                            // 68
  'def authorize_admin_action(user_role):',                                      // 69
  '    if not user_role:',                                                       // 70
  '        return False',                                                        // 71
  '    # Broken authorization bypass on line 73',                                // 72
  '    if user_role == "admin" or True:',                                        // 73
  '        return True',                                                         // 74
  '    return False',                                                            // 75
];

const VULNERABLE_PY = VULNERABLE_PY_LINES.join('\n') + '\n';

let tmpDir: string;
let server: http.Server;
let baseUrl: string;
const createdUserDirs: string[] = [];

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-vuln-reg-'));
  process.env.DATABASE_PATH = path.join(tmpDir, 'regression.db');
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

async function registerAndLogin(fullName: string, email: string) {
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

describe('Vulnerable Fixture End-to-End Regression Suite', () => {
  it('detects all vulnerable.py issues + line 66 syntax diagnostic cleanly', async () => {
    const res = await analyzePythonFileWithDiagnostics('vulnerable.py', 'vulnerable.py', VULNERABLE_PY);

    // 1. Line 66 syntax error diagnostic emitted cleanly
    expect(res.diagnostics.some((d) => d.kind === 'syntax_error' && d.line === 66)).toBe(true);

    // 2. All vulnerabilities across lines 12-13, 18, 29-30, 40, 47, 49-51, 73 detected despite line 66 syntax error
    const sqli12_13 = res.findings.find(
      (f) => f.category === 'SQL Injection' && f.startLine <= 13 && (f.endLine ?? f.startLine) >= 13
    );
    const md5_18 = res.findings.find(
      (f) => f.category === 'Weak Cryptography' && f.startLine === 18
    );
    const cmd_29_30 = res.findings.find(
      (f) => f.category === 'Command Injection' && f.startLine === 29 && f.endLine === 30
    );
    const sqli40 = res.findings.find(
      (f) => f.category === 'SQL Injection' && f.startLine === 40
    );
    const secret47 = res.findings.find(
      (f) => f.category === 'Hardcoded Credentials' && f.startLine === 47
    );
    const plaintextPwd = res.findings.find(
      (f) => f.category === 'Plaintext Password Storage' && f.startLine >= 49 && (f.endLine ?? f.startLine) <= 51
    );
    const brokenAuth73 = res.findings.find(
      (f) => f.category === 'Broken Authorization' && f.startLine === 73
    );

    expect(sqli12_13).toBeDefined();
    expect(md5_18).toBeDefined();
    expect(cmd_29_30).toBeDefined();
    expect(sqli40).toBeDefined();
    expect(secret47).toBeDefined();
    expect(plaintextPwd).toBeDefined();
    expect(brokenAuth73).toBeDefined();

    // Ensure line 40 SQL query is NOT corrupted by secret redaction
    expect(sqli40!.codeSnippet).toContain('SELECT * FROM profiles WHERE id =');
    // Ensure line 47 secret IS masked
    expect(secret47!.redactedEvidence).toContain('****');
    expect(secret47!.redactedEvidence).not.toContain('test_secret_credential_9876');
    expect(secret47!.codeSnippet).not.toContain('test_secret_credential_9876');
  });

  it('eliminates Semgrep "requires login" placeholder and hydrates real lines from disk', () => {
    const tmpScan = fs.mkdtempSync(path.join(tmpDir, 'semgrep-'));
    fs.writeFileSync(path.join(tmpScan, 'vulnerable.py'), VULNERABLE_PY, 'utf8');

    const semgrepPayload = JSON.stringify({
      results: [
        {
          check_id: 'python.lang.security.audit.formatted-sql-query',
          path: 'vulnerable.py',
          start: { line: 40, col: 5 },
          end: { line: 40, col: 68 },
          extra: {
            message: 'Possible SQL injection detected via string concatenation.',
            severity: 'ERROR',
            lines: 'requires login',
            metadata: { cwe: ['CWE-89: SQL Injection'], owasp: ['A03:2021 - Injection'] },
          },
        },
      ],
    });

    const parsed = parseSemgrepOutput(semgrepPayload, tmpScan);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].codeSnippet).not.toMatch(/requires login/i);
    expect(parsed[0].codeSnippet).toContain('cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)');
    expect(parsed[0].startCol).toBe(5);
    expect(parsed[0].endCol).toBe(68);

    const normalized = normalizeFinding(parsed[0], 'proj-semgrep');
    expect(normalized.codeSnippet).not.toMatch(/requires login/i);
    expect(normalized.redactedEvidence).toBeNull();
  });

  it('deduplicates overlapping same-family detections cleanly without merging distinct lines or categories', () => {
    const p1 = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-PY-SUBPROCESS-SHELL',
        title: 'Subprocess Invoked with shell=True',
        description: 'Detected subprocess.run(..., shell=True)',
        category: 'Command Injection',
        severity: 'High',
        confidence: 'High',
        cweId: 'CWE-78',
        filePath: 'vulnerable.py',
        startLine: 29,
        endLine: 30,
        startCol: 14,
        endCol: 58,
        language: 'Python',
        codeSnippet: 'result = subprocess.run(\n  cmd, shell=True)',
      },
      'proj-1'
    );
    const p2 = normalizeFinding(
      {
        scannerName: 'bandit',
        detectionSource: 'confirmed_tool',
        ruleId: 'B602',
        title: 'subprocess call with shell=True identified',
        description: 'Bandit detected shell=True subprocess invocation',
        category: 'Command Injection',
        severity: 'High',
        confidence: 'High',
        cweId: 'CWE-78',
        filePath: 'vulnerable.py',
        startLine: 29,
        endLine: 30,
        startCol: 14,
        endCol: 58,
        language: 'Python',
        codeSnippet: 'subprocess.run(cmd, shell=True)',
      },
      'proj-1'
    );
    const p3 = normalizeFinding(
      {
        scannerName: 'semgrep',
        detectionSource: 'confirmed_tool',
        ruleId: 'python.lang.security.audit.subprocess-shell-true',
        title: 'Semgrep shell=True',
        description: 'Semgrep detected subprocess shell=True',
        category: 'Command Injection',
        severity: 'Critical',
        confidence: 'High',
        cweId: 'CWE-78',
        filePath: 'vulnerable.py',
        startLine: 30,
        endLine: 30,
        language: 'Python',
        codeSnippet: 'requires login',
      },
      'proj-1'
    );
    // Different occurrence of SQLi (lines 12-13 vs line 40) must NOT merge
    const sqli1 = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-PY-SQLI',
        title: 'SQLi 1',
        description: 'SQLi on lines 12-13',
        category: 'SQL Injection',
        severity: 'Critical',
        confidence: 'High',
        cweId: 'CWE-89',
        filePath: 'vulnerable.py',
        startLine: 12,
        endLine: 13,
        language: 'Python',
      },
      'proj-1'
    );
    const sqli2 = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-PY-SQLI',
        title: 'SQLi 2',
        description: 'SQLi on line 40',
        category: 'SQL Injection',
        severity: 'Critical',
        confidence: 'High',
        cweId: 'CWE-89',
        filePath: 'vulnerable.py',
        startLine: 40,
        endLine: 40,
        language: 'Python',
      },
      'proj-1'
    );
    // Different vulnerability type on overlapping line must NOT merge
    const otherSameLine = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'confirmed_tool',
        ruleId: 'CUSTOM-PY-PLAINTEXT-PASSWORD',
        title: 'Plaintext Password',
        description: 'Plaintext password at line 40',
        category: 'Plaintext Password Storage',
        severity: 'High',
        confidence: 'High',
        cweId: 'CWE-256',
        filePath: 'vulnerable.py',
        startLine: 40,
        endLine: 40,
        language: 'Python',
      },
      'proj-1'
    );

    const deduped = deduplicateFindings([p1, p2, p3, sqli1, sqli2, otherSameLine]);
    expect(deduped).toHaveLength(4);

    const mergedCmd = deduped.find((f) => f.category === 'Command Injection');
    expect(mergedCmd).toBeDefined();
    expect(mergedCmd!.severity).toBe('Critical'); // Highest severity preserved
    expect(mergedCmd!.contributingScanners).toEqual(expect.arrayContaining(['custom', 'bandit', 'semgrep']));
    expect(mergedCmd!.scannerEvidence).toHaveLength(3);
    expect(mergedCmd!.redactedEvidence).toBeNull(); // Never overwritten with "Also flagged by..." or "requires login"
  });

  it('captures immutable per-scan snapshots, enforces ownership, handles legacy missing snapshots, and supports remediation validation', async () => {
    const studentA = await registerAndLogin('Student A', 'studenta-reg@cse.edu');
    const studentB = await registerAndLogin('Student B', 'studentb-reg@cse.edu');

    // Create project for Student A and upload vulnerable.py
    const projRes = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: studentA.cookie,
        'X-CSRF-Token': studentA.csrfToken,
      },
      body: JSON.stringify({ name: 'Vulnerable Py Project', description: 'Regression test' }),
    });
    expect(projRes.status).toBe(201);
    const { project } = (await projRes.json()) as { project: { id: string } };

    const form = new FormData();
    form.append('files', new Blob([VULNERABLE_PY], { type: 'text/x-python' }), 'vulnerable.py');
    const upRes = await fetch(`${baseUrl}/api/projects/${project.id}/upload`, {
      method: 'POST',
      headers: { Cookie: studentA.cookie, 'X-CSRF-Token': studentA.csrfToken },
      body: form,
    });
    expect(upRes.status).toBe(200);

    // Run Scan 1 (Custom AST/Rules)
    const scan1Res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: studentA.cookie,
        'X-CSRF-Token': studentA.csrfToken,
      },
      body: JSON.stringify({ projectId: project.id, scanners: ['custom'] }),
    });
    expect(scan1Res.status).toBe(201);
    const { scan: scan1 } = (await scan1Res.json()) as {
      scan: { id: string; totalFindings: number; diagnostics: Array<{ line: number; kind: string }> };
    };
    expect(scan1.totalFindings).toBeGreaterThanOrEqual(7);
    expect(scan1.diagnostics.some((d) => d.line === 66 && d.kind === 'syntax_error')).toBe(true);

    // Fetch Scan 1 findings and diagnostics via API
    const scan1FindingsRes = await fetch(`${baseUrl}/api/scans/${scan1.id}/findings`, {
      headers: { Cookie: studentA.cookie },
    });
    expect(scan1FindingsRes.status).toBe(200);
    const scan1FindingsBody = (await scan1FindingsRes.json()) as {
      findings: Array<{
        id: string;
        category: string;
        startLine: number;
        endLine: number;
        guidance?: { whyVulnerable: string; potentialImpact: string; recommendedApproach: string };
      }>;
      diagnostics: Array<{ line: number }>;
    };
    expect(scan1FindingsBody.diagnostics.some((d) => d.line === 66)).toBe(true);

    const sqli40Finding = scan1FindingsBody.findings.find(
      (f) => f.category === 'SQL Injection' && f.startLine === 40
    );
    const cmd29Finding = scan1FindingsBody.findings.find(
      (f) => f.category === 'Command Injection' && f.startLine === 29 && f.endLine === 30
    );
    const secret47Finding = scan1FindingsBody.findings.find(
      (f) => f.category === 'Hardcoded Credentials' && f.startLine === 47
    );
    expect(sqli40Finding).toBeDefined();
    expect(cmd29Finding).toBeDefined();
    expect(secret47Finding).toBeDefined();

    // Detail endpoint returns ~7 lines context around line 40, accurate line numbers, secret redaction on nearby lines if any, and guidance
    const detail40Res = await fetch(`${baseUrl}/api/findings/${sqli40Finding!.id}`, {
      headers: { Cookie: studentA.cookie },
    });
    expect(detail40Res.status).toBe(200);
    const detail40 = (await detail40Res.json()) as {
      finding: { redactedEvidence: string | null; codeSnippet: string };
      sourceContext: {
        available: boolean;
        fromSnapshot: boolean;
        contextStartLine: number;
        contextEndLine: number;
        lines: Array<{
          lineNumber: number;
          text: string;
          isTarget: boolean;
          highlightStartCol: number | null;
          highlightEndCol: number | null;
        }>;
      };
    };

    expect(detail40.sourceContext.available).toBe(true);
    expect(detail40.sourceContext.fromSnapshot).toBe(true);
    expect(detail40.sourceContext.contextStartLine).toBe(33);
    expect(detail40.sourceContext.contextEndLine).toBe(47);
    const line40Entry = detail40.sourceContext.lines.find((l) => l.lineNumber === 40);
    expect(line40Entry?.isTarget).toBe(true);
    expect(line40Entry?.text).toContain('cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)');
    expect(line40Entry?.highlightStartCol).not.toBeNull();
    expect(line40Entry?.highlightEndCol).not.toBeNull();
    // Line 47 falls inside context window 33..47 and MUST be secret-redacted!
    const line47InCtx = detail40.sourceContext.lines.find((l) => l.lineNumber === 47);
    expect(line47InCtx?.text).toContain('****');
    expect(line47InCtx?.text).not.toContain('test_secret_credential_9876');
    expect(detail40.finding.codeSnippet).not.toMatch(/requires login/i);

    // Multiline context (lines 29-30) highlights both lines 29 and 30
    const detailCmd = getFindingSourceContext({
      findingId: cmd29Finding!.id,
      userId: studentA.user.id,
      contextRadius: 7,
    });
    expect(detailCmd.lines.filter((l) => l.isTarget).map((l) => l.lineNumber)).toEqual([29, 30]);

    // Full file snapshot endpoint redacts secrets and preserves line 40 SQL
    const fullRes = await fetch(`${baseUrl}/api/findings/${sqli40Finding!.id}/source?full=true`, {
      headers: { Cookie: studentA.cookie },
    });
    expect(fullRes.status).toBe(200);
    const fullBody = (await fullRes.json()) as { file: { available: boolean; content: string } };
    expect(fullBody.file.available).toBe(true);
    expect(fullBody.file.content).toContain('SELECT * FROM profiles WHERE id =');
    expect(fullBody.file.content).not.toContain('test_secret_credential_9876');

    // Ownership isolation checks: Student B gets 404; unauthenticated gets 401 cleanly
    const crossFindingRes = await fetch(`${baseUrl}/api/findings/${sqli40Finding!.id}`, {
      headers: { Cookie: studentB.cookie },
    });
    expect(crossFindingRes.status).toBe(404);

    const crossSourceRes = await fetch(`${baseUrl}/api/findings/${sqli40Finding!.id}/source?full=true`, {
      headers: { Cookie: studentB.cookie },
    });
    expect(crossSourceRes.status).toBe(404);

    const crossDiagRes = await fetch(`${baseUrl}/api/scans/${scan1.id}/diagnostics`, {
      headers: { Cookie: studentB.cookie },
    });
    expect(crossDiagRes.status).toBe(404);

    const unauthRes = await fetch(`${baseUrl}/api/findings/${sqli40Finding!.id}`);
    expect(unauthRes.status).toBe(401);

    // Patch vulnerable.py on disk (fix line 40 SQLi) -> Scan 1 snapshot MUST remain immutable!
    const db = getDb();
    const projRow = db
      .prepare('SELECT source_path FROM projects WHERE id = ?')
      .get(project.id) as { source_path: string };
    const patchedPy = VULNERABLE_PY.replace(
      '    cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)',
      '    cursor.execute("SELECT * FROM profiles WHERE id = ?", (user_id,))'
    );
    fs.writeFileSync(path.join(projRow.source_path, 'vulnerable.py'), patchedPy, 'utf8');

    const snapshotAfterEdit = getFindingSourceContext({
      findingId: sqli40Finding!.id,
      userId: studentA.user.id,
    });
    expect(snapshotAfterEdit.available).toBe(true);
    expect(snapshotAfterEdit.lines.find((l) => l.lineNumber === 40)?.text).toContain('+ user_id');

    // Delete source file from disk -> snapshot STILL loads!
    fs.unlinkSync(path.join(projRow.source_path, 'vulnerable.py'));
    const snapshotAfterDelete = getFindingFullSnapshot({
      findingId: sqli40Finding!.id,
      userId: studentA.user.id,
    });
    expect(snapshotAfterDelete.available).toBe(true);
    expect(snapshotAfterDelete.content).toContain('+ user_id');

    // Legacy scan without snapshot (simulate deleted/missing snapshot row while disk file has modified content)
    fs.writeFileSync(path.join(projRow.source_path, 'vulnerable.py'), patchedPy, 'utf8');
    db.prepare('DELETE FROM scan_file_snapshots WHERE scan_id = ?').run(scan1.id);
    const legacyMissing = getFindingSourceContext({
      findingId: sqli40Finding!.id,
      userId: studentA.user.id,
    });
    expect(legacyMissing.available).toBe(false);
    expect(legacyMissing.snapshotNotice).toContain('unavailable');
    expect(legacyMissing.lines).toHaveLength(0);

    // Remediation approval, backup, and static rescan validation on a clean syntax-valid file
    const singleFileContent =
      'def get_profile(cursor, user_id):\n    cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)\n';
    const fixedSingleFile =
      'def get_profile(cursor, user_id):\n    cursor.execute("SELECT * FROM profiles WHERE id = ?", (user_id,))\n';
    fs.writeFileSync(path.join(projRow.source_path, 'profile_query.py'), singleFileContent, 'utf8');

    const scan2Res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: studentA.cookie,
        'X-CSRF-Token': studentA.csrfToken,
      },
      body: JSON.stringify({ projectId: project.id, scanners: ['custom'] }),
    });
    expect(scan2Res.status).toBe(201);
    const { scan: scan2 } = (await scan2Res.json()) as { scan: { id: string } };
    const profileFinding = db
      .prepare("SELECT id FROM findings WHERE scan_id = ? AND file_path = 'profile_query.py' LIMIT 1")
      .get(scan2.id) as { id: string };

    const remId = crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO remediation_proposals (id, finding_id, project_id, user_id, file_path, original_code, proposed_code, diff_summary, explanation, status, validation_status, created_at)
       VALUES (?, ?, ?, ?, 'profile_query.py', ?, ?, 'Parameterized SQL query', 'Use bound SQL placeholder', 'pending', 'pending', ?)`
    ).run(remId, profileFinding.id, project.id, studentA.user.id, singleFileContent, fixedSingleFile, now);

    const applied = approveAndApplyRemediation(remId, studentA.user.id);
    expect(applied.status).toBe('applied');
    expect(applied.backupPath).toBeTruthy();

    const validation = await validateRemediationFix(remId, studentA.user.id);
    expect(validation.originalRemains).toBe(false);
    expect(validation.proposal.validationStatus).toBe('validated');

    // AI location validation + payload checks (against scan2 snapshot of vulnerable.py / profile_query.py)
    const validLoc = validateAiReferencedLocations(
      'Vulnerability occurs in profile_query.py:2 (`cursor.execute`).',
      project.id,
      studentA.user.id,
      scan2.id
    );
    expect(validLoc.valid).toBe(true);
    expect(validLoc.unverifiedReferences).toHaveLength(0);

    const badLoc = validateAiReferencedLocations(
      'Check vulnerable.py line 999 and nonexistent.py:12.',
      project.id,
      studentA.user.id,
      scan2.id
    );
    expect(badLoc.valid).toBe(false);
    expect(badLoc.unverifiedReferences).toEqual(
      expect.arrayContaining(['vulnerable.py:999', 'nonexistent.py:12'])
    );

    const parsedBandit = parseBanditOutput(
      JSON.stringify({
        errors: [{ filename: '/tmp/proj/vulnerable.py', reason: 'syntax error while parsing AST from file' }],
        results: [],
      }),
      '/tmp/proj'
    );
    expect(parsedBandit).toHaveLength(0);

    // Ensure secret redactor preserves ordinary SQL strings while masking secrets
    expect(redactTextSecrets('cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)')).toBe(
      'cursor.execute("SELECT * FROM profiles WHERE id = " + user_id)'
    );

    expect(() =>
      validateAnalysisPayload({
        vulnerabilityMeaning: 'SQL Injection',
        whyUnsafe: 'String concatenation',
        exploitationScenario: 'OR 1=1',
        realWorldImpact: 'Data leak',
        riskContext: 'Critical',
        secureRecommendation: 'Parameterized query',
        cweOwaspContext: 'CWE-89',
        correctedCodeExample: 'cursor.execute("SELECT * FROM profiles WHERE id = ?", (user_id,))',
        falsePositiveAssessment: 'likely_genuine',
        falsePositiveReasoning: 'Direct concatenation',
        uncertaintyNote: 'Verify schema',
      })
    ).not.toThrow();

    expect(() =>
      validateFixPayload({
        proposedCode: fixedSingleFile,
        diffSummary: 'Parameterized SQL',
        explanation: 'Prevents SQL injection',
      })
    ).not.toThrow();
  });
});
