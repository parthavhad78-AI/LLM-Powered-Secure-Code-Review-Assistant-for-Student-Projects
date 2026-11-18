import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import PDFDocument from 'pdfkit';
import type { ReportRecord } from '../../shared/types.ts';
import { getDb } from '../database/db.ts';
import { redactTextSecrets } from '../scanners/security/secretRedactor.ts';

export function escapeCsvCell(val: unknown): string {
  let str = String(val ?? '');
  // Neutralize CSV formula injection (=, +, -, @, tab, CR)
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export async function generateAssessmentReport(params: {
  userId: string;
  projectId: string;
  scanId?: string | null;
  format: 'pdf' | 'csv';
  title?: string;
}): Promise<ReportRecord> {
  const db = getDb();

  const student = db
    .prepare('SELECT full_name, email FROM users WHERE id = ?')
    .get(params.userId) as { full_name: string; email: string } | undefined;

  const project = db
    .prepare('SELECT id, name, description, primary_language, languages_json FROM projects WHERE id = ? AND user_id = ?')
    .get(params.projectId, params.userId) as
    | { id: string; name: string; description: string; primary_language: string | null; languages_json: string }
    | undefined;

  if (!student || !project) {
    throw new Error('Project not found or access denied.');
  }

  const scan = params.scanId
    ? (db
        .prepare('SELECT * FROM scan_sessions WHERE id = ? AND project_id = ? AND user_id = ?')
        .get(params.scanId, params.projectId, params.userId) as Record<string, unknown> | undefined)
    : (db
        .prepare(
          'SELECT * FROM scan_sessions WHERE project_id = ? AND user_id = ? ORDER BY started_at DESC LIMIT 1'
        )
        .get(params.projectId, params.userId) as Record<string, unknown> | undefined);

  const effectiveScanId = scan ? String(scan.id) : null;

  const scannerResults = effectiveScanId
    ? (db
        .prepare('SELECT * FROM scanner_results WHERE scan_id = ? ORDER BY scanner_name ASC')
        .all(effectiveScanId) as Array<Record<string, unknown>>)
    : [];

  const findings = effectiveScanId
    ? (db
        .prepare(
          `SELECT f.*,
                  (SELECT vulnerability_meaning FROM ai_analyses a WHERE a.finding_id = f.id ORDER BY a.created_at DESC LIMIT 1) AS ai_meaning,
                  (SELECT false_positive_assessment FROM ai_analyses a WHERE a.finding_id = f.id ORDER BY a.created_at DESC LIMIT 1) AS ai_fp,
                  (SELECT secure_recommendation FROM ai_analyses a WHERE a.finding_id = f.id ORDER BY a.created_at DESC LIMIT 1) AS ai_rec,
                  (SELECT validation_status FROM remediation_proposals r WHERE r.finding_id = f.id ORDER BY r.created_at DESC LIMIT 1) AS rem_validation
           FROM findings f
           WHERE f.scan_id = ? AND f.user_id = ?
           ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, f.file_path ASC`
        )
        .all(effectiveScanId, params.userId) as Array<Record<string, unknown>>)
    : [];

  const summary = {
    totalFindings: findings.length,
    critical: findings.filter((f) => f.severity === 'Critical').length,
    high: findings.filter((f) => f.severity === 'High').length,
    medium: findings.filter((f) => f.severity === 'Medium').length,
    low: findings.filter((f) => f.severity === 'Low').length,
    informational: findings.filter((f) => f.severity === 'Informational').length,
    remediated: findings.filter((f) => f.remediation_status === 'remediated').length,
  };

  const reportId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const reportTitle =
    params.title?.trim() || `${project.name} Security Assessment (${params.format.toUpperCase()})`;

  const reportsDir = path.resolve(process.cwd(), 'data', 'reports', params.userId.replace(/[^a-zA-Z0-9_-]/g, ''));
  fs.mkdirSync(reportsDir, { recursive: true });
  const fileName = `${reportId}.${params.format}`;
  const absReportPath = path.join(reportsDir, fileName);

  if (params.format === 'csv') {
    const header = [
      'Finding ID',
      'Project Name',
      'Scan ID',
      'Scanner',
      'Detection Source',
      'Rule ID',
      'Title',
      'Category',
      'Severity',
      'Confidence',
      'File Path',
      'Start Line',
      'End Line',
      'CWE',
      'OWASP',
      'Remediation Status',
      'Fix Validation Status',
      'Scanner Description',
      'AI Vulnerability Summary (Advisory)',
      'AI False-Positive Assessment (Advisory)',
      'Detected At',
    ];

    const rows = findings.map((f) =>
      [
        f.id,
        project.name,
        f.scan_id,
        f.scanner_name,
        f.detection_source,
        f.rule_id,
        f.title,
        f.category,
        f.severity,
        f.confidence,
        f.file_path,
        f.start_line,
        f.end_line,
        f.cwe_id || '',
        f.owasp_category || '',
        f.remediation_status,
        f.rem_validation || 'none',
        redactTextSecrets(String(f.description || '')),
        f.ai_meaning ? redactTextSecrets(String(f.ai_meaning)) : '',
        f.ai_fp || '',
        f.detected_at,
      ]
        .map(escapeCsvCell)
        .join(',')
    );

    const csvContent = [header.map(escapeCsvCell).join(','), ...rows].join('\r\n');
    fs.writeFileSync(absReportPath, csvContent, 'utf8');
  } else {
    await writePdfReport({
      absReportPath,
      reportTitle,
      student,
      project,
      scan,
      scannerResults,
      findings,
      summary,
      createdAt,
    });
  }

  db.prepare(
    `INSERT INTO reports (id, user_id, project_id, scan_id, title, format, file_path, summary_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    reportId,
    params.userId,
    params.projectId,
    effectiveScanId,
    reportTitle,
    params.format,
    fileName,
    JSON.stringify(summary),
    createdAt
  );

  return {
    id: reportId,
    userId: params.userId,
    projectId: params.projectId,
    projectName: project.name,
    scanId: effectiveScanId,
    title: reportTitle,
    format: params.format,
    summary,
    createdAt,
  };
}

function writePdfReport(ctx: {
  absReportPath: string;
  reportTitle: string;
  student: { full_name: string; email: string };
  project: { id: string; name: string; description: string; primary_language: string | null };
  scan: Record<string, unknown> | undefined;
  scannerResults: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    remediated: number;
  };
  createdAt: string;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48, size: 'A4' });
    const stream = fs.createWriteStream(ctx.absReportPath);
    doc.pipe(stream);

    // Header
    doc.fontSize(20).fillColor('#0f172a').text('SecureLens Security Assessment Report');
    doc.moveDown(0.3);
    doc.fontSize(12).fillColor('#334155').text(ctx.reportTitle);
    doc.moveDown(0.5);
    doc.moveTo(48, doc.y).lineTo(547, doc.y).strokeColor('#cbd5e1').stroke();
    doc.moveDown(0.8);

    // Metadata block
    doc.fontSize(10).fillColor('#1e293b');
    doc.text(`Student: ${ctx.student.full_name} (${ctx.student.email})`);
    doc.text(`Project: ${ctx.project.name} (Primary Language: ${ctx.project.primary_language || 'Mixed'})`);
    doc.text(`Scan Date: ${ctx.scan ? String(ctx.scan.started_at) : 'No scan recorded'}`);
    doc.text(`Report Generated: ${ctx.createdAt}`);
    doc.moveDown(0.8);

    // Severity summary
    doc.fontSize(13).fillColor('#0f172a').text('1. Executive Severity Summary');
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor('#1e293b');
    doc.text(
      `Total Findings: ${ctx.summary.totalFindings}  |  Critical: ${ctx.summary.critical}  |  High: ${ctx.summary.high}  |  Medium: ${ctx.summary.medium}  |  Low: ${ctx.summary.low}  |  Informational: ${ctx.summary.informational}  |  Remediated: ${ctx.summary.remediated}`
    );
    doc.moveDown(0.8);

    // Scanners used
    doc.fontSize(13).fillColor('#0f172a').text('2. Scanner Execution Status');
    doc.moveDown(0.3);
    doc.fontSize(9.5).fillColor('#1e293b');
    if (ctx.scannerResults.length === 0) {
      doc.text('No scanner execution records found for this report.');
    } else {
      for (const sr of ctx.scannerResults) {
        doc.text(
          `- ${sr.scanner_name} (${sr.version || 'unavailable'}): ${sr.status} | Findings: ${sr.findings_count} | Duration: ${sr.duration_ms}ms`
        );
      }
    }
    doc.moveDown(0.8);

    // Findings detail
    doc.fontSize(13).fillColor('#0f172a').text('3. Detailed Vulnerability Findings');
    doc.moveDown(0.4);

    if (ctx.findings.length === 0) {
      doc.fontSize(10).fillColor('#475569').text('Zero findings recorded in the selected scan.');
    } else {
      ctx.findings.forEach((f, idx) => {
        if (doc.y > 700) doc.addPage();
        doc.fontSize(10.5).fillColor('#0f172a').text(
          `${idx + 1}. [${f.severity}] ${f.title} (${f.rule_id})`
        );
        doc.fontSize(9).fillColor('#334155').text(
          `Location: ${f.file_path}:${f.start_line}-${f.end_line}  |  Scanner: ${f.scanner_name} (${f.detection_source})  |  Status: ${f.remediation_status}`
        );
        doc.text(
          `References: ${f.cwe_id || 'N/A'}  |  ${f.owasp_category || 'N/A'}  |  Fix Validation: ${f.rem_validation || 'Not run'}`
        );
        doc.fillColor('#1e293b').text(`Scanner Evidence: ${redactTextSecrets(String(f.description || ''))}`);
        if (f.ai_meaning) {
          doc.fillColor('#0369a1').text(
            `[AI Advisory Commentary — Non-Authoritative] ${redactTextSecrets(String(f.ai_meaning))} (Assessment: ${f.ai_fp || 'N/A'})`
          );
        }
        doc.moveDown(0.6);
      });
    }

    doc.end();
    stream.on('finish', resolve);
    stream.on('error', reject);
  });
}
