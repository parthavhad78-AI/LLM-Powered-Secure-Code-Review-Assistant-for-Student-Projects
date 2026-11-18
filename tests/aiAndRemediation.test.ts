import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { validateAnalysisPayload, validateFixPayload } from '../server/ai/aiService.ts';
import { GeminiServiceError } from '../server/ai/geminiClient.ts';
import { registerStudent } from '../server/auth/authService.ts';
import { closeDb, getDb, initDatabase } from '../server/database/db.ts';
import {
  approveAndApplyRemediation,
  rejectRemediation,
  validateRemediationFix,
} from '../server/remediation/remediationService.ts';
import { executeProjectScan } from '../server/scanners/scannerManager.ts';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-rem-test-'));
  initDatabase(path.join(tmpDir, 'test.db'));
});

afterEach(() => {
  closeDb();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('Gemini AI Response Validation & Failure Handling', () => {
  it('validates structured AI vulnerability analysis payloads and rejects malformed responses', () => {
    expect(() => validateAnalysisPayload(null)).toThrow(GeminiServiceError);
    expect(() => validateAnalysisPayload({ vulnerabilityMeaning: 'partial' })).toThrow(
      'missing required field'
    );

    const valid = validateAnalysisPayload({
      vulnerabilityMeaning: 'eval runs arbitrary code',
      whyUnsafe: 'Attackers control string input',
      exploitationScenario: 'Inject process.exit()',
      realWorldImpact: 'Server takeover',
      riskContext: 'Critical severity',
      secureRecommendation: 'Use JSON.parse()',
      cweOwaspContext: 'CWE-95 / A03',
      correctedCodeExample: 'JSON.parse(input)',
      falsePositiveAssessment: 'likely_genuine',
      falsePositiveReasoning: 'Direct call observed',
      uncertaintyNote: 'Verify caller sanitization',
    });

    expect(valid.falsePositiveAssessment).toBe('likely_genuine');
  });

  it('validates AI code fix payloads', () => {
    expect(() => validateFixPayload({ proposedCode: '' })).toThrow(GeminiServiceError);

    const fix = validateFixPayload({
      proposedCode: 'JSON.parse(x);',
      diffSummary: 'Replaced eval with JSON.parse',
      explanation: 'Eliminates arbitrary code execution.',
    });
    expect(fix.proposedCode).toBe('JSON.parse(x);');
  });
});

describe('Remediation Approval, Rejection, Backups & Static Fix Validation', () => {
  it('applies an approved fix with backup snapshot and validates resolution via static rescan', async () => {
    const user = await registerStudent({
      fullName: 'Ananya Rao',
      email: 'ananya@cse.edu',
      password: 'Password123!',
      confirmPassword: 'Password123!',
    });

    const projectId = crypto.randomUUID();
    const projSourceDir = path.join(process.cwd(), 'data', 'projects', user.id.replace(/[^a-zA-Z0-9_-]/g, ''), projectId, 'source');
    fs.mkdirSync(projSourceDir, { recursive: true });
    const vulnerableCode = 'export function calc(input) {\n  return eval(input);\n}\n';
    fs.writeFileSync(path.join(projSourceDir, 'calc.js'), vulnerableCode, 'utf8');

    const db = getDb();
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO projects (id, user_id, name, description, primary_language, languages_json, source_path, file_count, total_bytes, created_at, updated_at)
       VALUES (?, ?, 'Calc App', '', 'JavaScript', '["JavaScript"]', ?, 1, ?, ?, ?)`
    ).run(projectId, user.id, projSourceDir, vulnerableCode.length, now, now);

    // 1. Scan vulnerable file
    const scan = await executeProjectScan({
      userId: user.id,
      projectId,
      sourcePath: projSourceDir,
      scanners: ['custom', 'eslint'],
    });
    expect(scan.totalFindings).toBeGreaterThan(0);

    const findingRow = db
      .prepare('SELECT id FROM findings WHERE scan_id = ? LIMIT 1')
      .get(scan.id) as { id: string };

    // 2. Insert two proposals: test rejection on one, approval + validation on the other
    const rejectPropId = crypto.randomUUID();
    db.prepare(
      `INSERT INTO remediation_proposals (id, finding_id, project_id, user_id, file_path, original_code, proposed_code, diff_summary, explanation, status, validation_status, created_at)
       VALUES (?, ?, ?, ?, 'calc.js', ?, ?, 'No-op', 'Test reject', 'pending', 'pending', ?)`
    ).run(rejectPropId, findingRow.id, projectId, user.id, vulnerableCode, vulnerableCode, now);

    const rejected = rejectRemediation(rejectPropId, user.id, 'Does not fix issue');
    expect(rejected.status).toBe('rejected');

    const approvePropId = crypto.randomUUID();
    const fixedCode = 'export function calc(input) {\n  return JSON.parse(input);\n}\n';
    db.prepare(
      `INSERT INTO remediation_proposals (id, finding_id, project_id, user_id, file_path, original_code, proposed_code, diff_summary, explanation, status, validation_status, created_at)
       VALUES (?, ?, ?, ?, 'calc.js', ?, ?, 'Replaced eval with JSON.parse', 'Safe parsing', 'pending', 'pending', ?)`
    ).run(approvePropId, findingRow.id, projectId, user.id, vulnerableCode, fixedCode, now);

    const applied = approveAndApplyRemediation(approvePropId, user.id);
    expect(applied.status).toBe('applied');
    expect(applied.backupPath).toBeTruthy();
    expect(fs.readFileSync(path.join(projSourceDir, 'calc.js'), 'utf8')).toBe(fixedCode);

    // 3. Validate fix via static rescan
    const validation = await validateRemediationFix(approvePropId, user.id);
    expect(validation.originalRemains).toBe(false);
    expect(validation.newIssuesCount).toBe(0);
    expect(validation.proposal.validationStatus).toBe('validated');

    // Cleanup disk workspace created under data/projects/<userId>
    fs.rmSync(path.join(process.cwd(), 'data', 'projects', user.id.replace(/[^a-zA-Z0-9_-]/g, '')), {
      recursive: true,
      force: true,
    });
  });
});
