import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseBanditOutput } from '../server/scanners/adapters/banditAdapter.ts';
import { eslintAdapter, parseEslintResults } from '../server/scanners/adapters/eslintAdapter.ts';
import { parseGitleaksOutput } from '../server/scanners/adapters/gitleaksAdapter.ts';
import { parseOsvOutput } from '../server/scanners/adapters/osvAdapter.ts';
import { runSafeProcess } from '../server/scanners/adapters/processRunner.ts';
import { parseSemgrepOutput } from '../server/scanners/adapters/semgrepAdapter.ts';
import { deduplicateFindings, normalizeFinding } from '../server/scanners/normalization/normalizer.ts';
import { analyzeJsTsAst, analyzePythonFile } from '../server/scanners/rules/customRules.ts';
import { runWithConcurrency } from '../server/scanners/scannerManager.ts';
import { redactSecretValue, redactTextSecrets } from '../server/scanners/security/secretRedactor.ts';

describe('Custom Security Rules (Positive & Negative Examples)', () => {
  it('detects Python vulnerabilities while avoiding false positives on safe code', async () => {
    const vulnerablePy = `
import os, pickle, yaml, hashlib, requests
API_KEY = "sk_live_abcdef1234567890"
def run_bad(user_input, cursor):
    eval(user_input)
    os.system("ls " + user_input)
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    pickle.loads(user_input)
    yaml.load(user_input)
    requests.get("https://example.com", verify=False)
`;
    const findings = await analyzePythonFile('vuln.py', 'vuln.py', vulnerablePy);
    const ruleIds = findings.map((f) => f.ruleId);

    expect(ruleIds).toContain('CUSTOM-PY-EVAL');
    expect(ruleIds).toContain('CUSTOM-PY-OS-SYSTEM');
    expect(ruleIds).toContain('CUSTOM-PY-SQLI');
    expect(ruleIds).toContain('CUSTOM-PY-PICKLE');
    expect(ruleIds).toContain('CUSTOM-PY-YAML-LOAD');
    expect(ruleIds).toContain('CUSTOM-PY-TLS-VERIFY-FALSE');
    expect(ruleIds.some((r) => r.includes('SECRET'))).toBe(true);

    const safePy = `
import os, json, yaml, subprocess, requests
API_KEY = os.environ.get("API_KEY")
def run_safe(user_input, cursor):
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    data = json.loads(user_input)
    cfg = yaml.safe_load("a: 1")
    subprocess.run(["echo", user_input], shell=False)
    requests.get("https://example.com", verify=True)
    return data, cfg
`;
    const safeFindings = await analyzePythonFile('safe.py', 'safe.py', safePy);
    expect(safeFindings).toHaveLength(0);
  });

  it('detects JavaScript/TypeScript vulnerabilities while avoiding false positives on safe code', () => {
    const vulnerableJs = `
const token = Math.random().toString(36);
function render(userHtml, userId, db, res, q) {
  eval(userHtml);
  document.write(userHtml);
  document.getElementById('bio').innerHTML = userHtml;
  db.query(\`SELECT * FROM items WHERE id = \${userId}\`);
  res.redirect(q.next);
}
`;
    const findings = analyzeJsTsAst('bad.js', vulnerableJs, 'JavaScript');
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('CUSTOM-JS-EVAL');
    expect(ruleIds).toContain('CUSTOM-JS-DOC-WRITE');
    expect(ruleIds).toContain('CUSTOM-JS-INNERHTML');
    expect(ruleIds).toContain('CUSTOM-JS-SQLI');
    expect(ruleIds).toContain('CUSTOM-JS-WEAK-RANDOM');
    expect(ruleIds).toContain('CUSTOM-JS-OPEN-REDIRECT');

    const safeJs = `
import crypto from 'node:crypto';
function renderSafe(userText, userId, db, res) {
  const token = crypto.randomBytes(16).toString('hex');
  document.getElementById('bio').textContent = userText;
  db.query('SELECT * FROM items WHERE id = ?', [userId]);
  res.redirect('/dashboard');
  return token;
}
`;
    const safeFindings = analyzeJsTsAst('safe.js', safeJs, 'JavaScript');
    expect(safeFindings).toHaveLength(0);
  });
});

describe('External Scanner Output Parsers & Normalization', () => {
  it('parses Bandit JSON output accurately', () => {
    const mockBandit = JSON.stringify({
      results: [
        {
          test_id: 'B605',
          test_name: 'start_process_with_a_shell',
          issue_severity: 'HIGH',
          issue_confidence: 'HIGH',
          issue_text: 'Starting a process with a shell: Seems safe, but may be changed in the future.',
          filename: '/tmp/scan/app.py',
          line_number: 14,
          line_range: [14],
          code: 'os.system("ls")',
          issue_cwe: { id: 78 },
        },
      ],
    });
    const parsed = parseBanditOutput(mockBandit, '/tmp/scan');
    expect(parsed).toHaveLength(1);
    expect(parsed[0].ruleId).toBe('B605');
    expect(parsed[0].cweId).toBe('CWE-78');
    expect(parsed[0].filePath).toBe('app.py');
    expect(parsed[0].severity).toBe('High');
  });

  it('parses Semgrep JSON output accurately', () => {
    const mockSemgrep = JSON.stringify({
      results: [
        {
          check_id: 'python.lang.security.audit.eval-detected',
          path: 'routes/calc.py',
          start: { line: 9 },
          end: { line: 9 },
          extra: {
            message: 'Detected use of eval()',
            severity: 'ERROR',
            lines: 'result = eval(expr)',
            metadata: { cwe: ['CWE-95: Improper Neutralization'], owasp: ['A03:2021 - Injection'] },
          },
        },
      ],
    });
    const parsed = parseSemgrepOutput(mockSemgrep, '.');
    expect(parsed).toHaveLength(1);
    expect(parsed[0].cweId).toBe('CWE-95');
    expect(parsed[0].severity).toBe('High');
    expect(parsed[0].filePath).toBe('routes/calc.py');
  });

  it('parses Gitleaks JSON output and strictly redacts exposed secrets', () => {
    const rawSecret = 'ghp_1234567890abcdefghij1234567890abcdef';
    const mockGitleaks = JSON.stringify([
      {
        RuleID: 'github-pat',
        Description: 'GitHub Personal Access Token',
        StartLine: 3,
        EndLine: 3,
        File: 'config.py',
        Match: `TOKEN = "${rawSecret}"`,
        Secret: rawSecret,
      },
    ]);
    const parsed = parseGitleaksOutput(mockGitleaks, '.');
    expect(parsed).toHaveLength(1);
    expect(parsed[0].codeSnippet).not.toContain(rawSecret);
    expect(parsed[0].redactedEvidence).not.toContain(rawSecret);
    expect(parsed[0].redactedEvidence).toContain('****');
  });

  it('parses ESLint security results and runs embedded ESLint without student config execution', async () => {
    const mockEslint = parseEslintResults(
      [
        {
          filePath: '/proj/index.js',
          messages: [
            { ruleId: 'security/detect-eval-with-expression', severity: 2, message: 'eval with argument', line: 5 },
            { ruleId: 'no-unused-vars', severity: 1, message: 'unused var', line: 2 },
          ],
        },
      ],
      '/proj'
    );
    expect(mockEslint).toHaveLength(1);
    expect(mockEslint[0].ruleId).toBe('security/detect-eval-with-expression');

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-eslint-'));
    try {
      fs.writeFileSync(path.join(tmp, 'sample.js'), 'function run(x) { return eval(x); }\n');
      const res = await eslintAdapter.scan(tmp, { timeoutMs: 10000 });
      expect(res.status).toBe('completed');
      expect(res.findings.some((f) => f.ruleId === 'security/detect-eval-with-expression')).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('parses OSV-Scanner JSON output and extracts fixed versions', () => {
    const mockOsv = JSON.stringify({
      results: [
        {
          source: { path: '/proj/package-lock.json' },
          packages: [
            {
              package: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
              vulnerabilities: [
                {
                  id: 'GHSA-jf85-cpcp-j695',
                  aliases: ['CVE-2020-8203'],
                  summary: 'Prototype Pollution in lodash',
                  database_specific: { severity: 'HIGH' },
                  affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
                },
              ],
            },
          ],
        },
      ],
    });
    const parsed = parseOsvOutput(mockOsv, '/proj');
    expect(parsed).toHaveLength(1);
    expect(parsed[0].ruleId).toBe('CVE-2020-8203');
    expect(parsed[0].recommendation).toContain('4.17.21');
  });

  it('redacts secrets in text and normalizes/deduplicates findings', () => {
    const masked = redactSecretValue('sk_live_1234567890abcdef');
    expect(masked).toBe('sk_l****************cdef');

    const text = redactTextSecrets('const db = "postgres://admin:SuperSecretPass99@localhost:5432/app";');
    expect(text).not.toContain('SuperSecretPass99');

    const n1 = normalizeFinding(
      {
        scannerName: 'custom',
        detectionSource: 'pattern_based',
        ruleId: 'CUSTOM-PY-EVAL-PATTERN',
        title: 'Pattern Eval',
        description: 'eval',
        category: 'Code Injection',
        severity: 'Critical',
        confidence: 'Medium',
        cweId: 'CWE-95',
        filePath: 'app.py',
        startLine: 10,
        language: 'Python',
      },
      'proj-1'
    );
    const n2 = normalizeFinding(
      {
        scannerName: 'bandit',
        detectionSource: 'confirmed_tool',
        ruleId: 'B307',
        title: 'Bandit Eval',
        description: 'eval confirmed',
        category: 'Code Injection',
        severity: 'Medium',
        confidence: 'High',
        cweId: 'CWE-95',
        filePath: 'app.py',
        startLine: 10,
        language: 'Python',
      },
      'proj-1'
    );
    const deduped = deduplicateFindings([n1, n2]);
    expect(deduped).toHaveLength(1);
    expect(deduped[0].scannerName).toBe('bandit');
  });
});

describe('Process Timeouts, Cancellation & Partial Failure Isolation', () => {
  it('enforces process timeouts and AbortSignal cancellation', async () => {
    const timeoutRes = await runSafeProcess({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      cwd: process.cwd(),
      timeoutMs: 120,
    });
    expect(timeoutRes.timedOut).toBe(true);

    const ac = new AbortController();
    setTimeout(() => ac.abort(), 80);
    const cancelRes = await runSafeProcess({
      command: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      cwd: process.cwd(),
      timeoutMs: 5000,
      signal: ac.signal,
    });
    expect(cancelRes.cancelled).toBe(true);
  });

  it('isolates partial scanner failures inside concurrent pools', async () => {
    const results = await runWithConcurrency(
      [
        async () => ({ ok: true, id: 1 }),
        async () => {
          throw new Error('boom');
        },
        async () => ({ ok: true, id: 3 }),
      ].map((fn) => async () => {
        try {
          return await fn();
        } catch {
          return { ok: false, id: 2 };
        }
      }),
      2
    );
    expect(results).toEqual([
      { ok: true, id: 1 },
      { ok: false, id: 2 },
      { ok: true, id: 3 },
    ]);
  });
});
