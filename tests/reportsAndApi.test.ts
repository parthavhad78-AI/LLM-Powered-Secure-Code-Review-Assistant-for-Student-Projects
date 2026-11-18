import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../server.ts';
import { closeDb } from '../server/database/db.ts';
import { escapeCsvCell, generateAssessmentReport } from '../server/reports/reportService.ts';

let tmpDir: string;
let server: http.Server;
let baseUrl: string;

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-api-test-'));
  process.env.DATABASE_PATH = path.join(tmpDir, 'api_test.db');
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
});

describe('End-to-End Student Isolation, Scanning & Report Generation', () => {
  it('neutralizes CSV formula injection payloads', () => {
    expect(escapeCsvCell('=CMD("calc")')).toBe("'=CMD(\"\"calc\"\")".includes('"') ? `"'=CMD(""calc"")"` : '');
    const neutralized = escapeCsvCell('=1+1');
    expect(neutralized.startsWith("'=")).toBe(true);
  });

  it('enforces student ownership across projects, scans, findings, and generates PDF/CSV reports', async () => {
    // 1. Register Student A
    const regA = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Student A',
        email: 'studenta@cse.edu',
        password: 'Password123!',
        confirmPassword: 'Password123!',
      }),
    });
    expect(regA.status).toBe(201);
    const cookieA = regA.headers.get('set-cookie')?.split(';')[0] || '';
    const bodyA = (await regA.json()) as { user: { id: string }; csrfToken: string };

    // 2. Register Student B
    const regB = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Student B',
        email: 'studentb@cse.edu',
        password: 'Password123!',
        confirmPassword: 'Password123!',
      }),
    });
    expect(regB.status).toBe(201);
    const cookieB = regB.headers.get('set-cookie')?.split(';')[0] || '';
    const bodyB = (await regB.json()) as { user: { id: string }; csrfToken: string };

    // 3. Student A creates project
    const projRes = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieA,
        'X-CSRF-Token': bodyA.csrfToken,
      },
      body: JSON.stringify({ name: 'Private Auth App', description: 'Student A workspace' }),
    });
    expect(projRes.status).toBe(201);
    const projBody = (await projRes.json()) as { project: { id: string } };

    // 4. Student B tries to access or delete Student A's project -> blocked (404)
    const crossGet = await fetch(`${baseUrl}/api/projects/${projBody.project.id}`, {
      headers: { Cookie: cookieB },
    });
    expect(crossGet.status).toBe(404);

    const crossDelete = await fetch(`${baseUrl}/api/projects/${projBody.project.id}`, {
      method: 'DELETE',
      headers: { Cookie: cookieB, 'X-CSRF-Token': bodyB.csrfToken },
    });
    expect(crossDelete.status).toBe(404);

    // 5. Student A uploads vulnerable JS file
    const form = new FormData();
    form.append('files', new Blob(['const x = eval("1+1");\n'], { type: 'text/javascript' }), 'index.js');
    const upRes = await fetch(`${baseUrl}/api/projects/${projBody.project.id}/upload`, {
      method: 'POST',
      headers: { Cookie: cookieA, 'X-CSRF-Token': bodyA.csrfToken },
      body: form,
    });
    expect(upRes.status).toBe(200);

    // 6. Student A runs scan
    const scanRes = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieA,
        'X-CSRF-Token': bodyA.csrfToken,
      },
      body: JSON.stringify({ projectId: projBody.project.id, scanners: ['custom', 'eslint'] }),
    });
    expect(scanRes.status).toBe(201);
    const scanBody = (await scanRes.json()) as { scan: { id: string; totalFindings: number } };
    expect(scanBody.scan.totalFindings).toBeGreaterThan(0);

    // 7. Generate PDF and CSV reports and verify Student B cannot download Student A's report
    const pdfReport = await generateAssessmentReport({
      userId: bodyA.user.id,
      projectId: projBody.project.id,
      scanId: scanBody.scan.id,
      format: 'pdf',
    });
    const csvReport = await generateAssessmentReport({
      userId: bodyA.user.id,
      projectId: projBody.project.id,
      scanId: scanBody.scan.id,
      format: 'csv',
    });

    const dlPdf = await fetch(`${baseUrl}/api/reports/${pdfReport.id}/download`, {
      headers: { Cookie: cookieA },
    });
    expect(dlPdf.status).toBe(200);
    expect(dlPdf.headers.get('content-type')).toContain('application/pdf');

    const dlCsv = await fetch(`${baseUrl}/api/reports/${csvReport.id}/download`, {
      headers: { Cookie: cookieA },
    });
    expect(dlCsv.status).toBe(200);
    const csvText = await dlCsv.text();
    expect(csvText).toContain('Finding ID');
    expect(csvText).toContain('index.js');

    const crossReport = await fetch(`${baseUrl}/api/reports/${pdfReport.id}/download`, {
      headers: { Cookie: cookieB },
    });
    expect(crossReport.status).toBe(404);

    // Cleanup Student A project & report files
    await fetch(`${baseUrl}/api/projects/${projBody.project.id}`, {
      method: 'DELETE',
      headers: { Cookie: cookieA, 'X-CSRF-Token': bodyA.csrfToken },
    });
    fs.rmSync(path.join(process.cwd(), 'data', 'reports', bodyA.user.id.replace(/[^a-zA-Z0-9_-]/g, '')), {
      recursive: true,
      force: true,
    });
  });
});
