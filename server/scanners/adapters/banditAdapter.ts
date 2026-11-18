import fs from 'node:fs';
import path from 'node:path';
import type { ConfidenceLevel, ScannerHealth, Severity } from '../../../shared/types.ts';
import type { RawScanDiagnostic, RawScannerFinding } from '../normalization/normalizer.ts';
import { collectDirectoryFiles } from '../security/fileSecurity.ts';
import { isAuthPlaceholderText, redactTextSecrets } from '../security/secretRedactor.ts';
import type { ScannerAdapter, ScannerAdapterResult } from './customAdapter.ts';
import { runSafeProcess } from './processRunner.ts';

function getBanditBinary(): string {
  return process.env.BANDIT_PATH || 'bandit';
}

const BANDIT_INSTALL_WIN = 'pip install bandit  # or: py -m pip install bandit';
const BANDIT_INSTALL_LINUX = 'pip3 install bandit';

interface BanditJsonIssue {
  test_id?: string;
  test_name?: string;
  issue_severity?: string;
  issue_confidence?: string;
  issue_text?: string;
  filename?: string;
  line_number?: number;
  line_range?: number[];
  col_offset?: number;
  end_col_offset?: number;
  code?: string;
  issue_cwe?: { id?: number; link?: string };
  more_info?: string;
}

interface BanditJsonError {
  filename?: string;
  reason?: string;
}

function normalizeRelPath(rawFile: string, normalizedRoot: string): string {
  return path.isAbsolute(rawFile)
    ? path.relative(normalizedRoot, rawFile).replace(/\\/g, '/')
    : rawFile.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function parseBanditDiagnostics(stdout: string, targetDir: string): RawScanDiagnostic[] {
  if (!stdout.trim()) return [];
  const parsed = JSON.parse(stdout) as { errors?: BanditJsonError[] };
  const errors = parsed.errors || [];
  const normalizedRoot = path.resolve(targetDir);

  return errors.map((err) => {
    const reason = String(err.reason || 'Bandit failed to parse file.');
    const lineMatch = reason.match(/line\s+(\d+)/i);
    return {
      scannerName: 'bandit',
      filePath: normalizeRelPath(err.filename || 'unknown.py', normalizedRoot),
      line: lineMatch ? Math.max(1, Number(lineMatch[1])) : 1,
      column: null,
      unlocated: !lineMatch,
      severity: 'error',
      kind: /syntax/i.test(reason) ? 'syntax_error' : 'parse_warning',
      message: reason,
    };
  });
}

export function parseBanditOutput(stdout: string, targetDir: string): RawScannerFinding[] {
  if (!stdout.trim()) return [];
  const parsed = JSON.parse(stdout) as { results?: BanditJsonIssue[] };
  const results = parsed.results || [];
  const normalizedRoot = path.resolve(targetDir);

  return results.map((issue) => {
    const relPath = normalizeRelPath(issue.filename || 'unknown.py', normalizedRoot);

    const sevMap: Record<string, Severity> = {
      HIGH: 'High',
      MEDIUM: 'Medium',
      LOW: 'Low',
    };
    const confMap: Record<string, ConfidenceLevel> = {
      HIGH: 'High',
      MEDIUM: 'Medium',
      LOW: 'Low',
    };

    const sev = sevMap[(issue.issue_severity || '').toUpperCase()] || 'Medium';
    const conf = confMap[(issue.issue_confidence || '').toUpperCase()] || 'Medium';
    const lineRange = issue.line_range || [];
    const startLine = issue.line_number || lineRange[0] || 1;
    const endLine = lineRange.length > 0 ? lineRange[lineRange.length - 1] : startLine;
    const startCol = typeof issue.col_offset === 'number' && issue.col_offset >= 0 ? issue.col_offset + 1 : null;
    const endCol =
      typeof issue.end_col_offset === 'number' && issue.end_col_offset >= 0
        ? issue.end_col_offset + 1
        : null;
    const cweId = issue.issue_cwe?.id ? `CWE-${issue.issue_cwe.id}` : null;

    const rawCode = issue.code || '';
    const safeSnippet = isAuthPlaceholderText(rawCode) ? '' : redactTextSecrets(rawCode);

    return {
      scannerName: 'bandit',
      detectionSource: 'confirmed_tool',
      ruleId: issue.test_id || 'BANDIT-UNKNOWN',
      title: issue.test_name ? `Bandit: ${issue.test_name.replace(/_/g, ' ')}` : 'Bandit Security Finding',
      description: issue.issue_text || 'Bandit static analysis flagged a Python security issue.',
      category: mapBanditCategory(issue.test_id || '', issue.issue_text || ''),
      severity: sev,
      confidence: conf,
      cweId,
      filePath: relPath,
      startLine,
      endLine,
      startCol,
      endCol,
      language: 'Python',
      codeSnippet: safeSnippet,
      recommendation: 'Review the Bandit finding and apply secure Python coding practices.',
      references: issue.more_info ? [issue.more_info] : [],
    };
  });
}

function mapBanditCategory(testId: string, text: string): string {
  if (testId.toUpperCase() === 'B404') return 'Security Misconfiguration';
  const combined = `${testId} ${text}`.toLowerCase();
  if (combined.includes('sql')) return 'SQL Injection';
  if (combined.includes('shell') || combined.includes('subprocess') || combined.includes('popen')) return 'Command Injection';
  if (combined.includes('pickle') || combined.includes('yaml')) return 'Insecure Deserialization';
  if (combined.includes('hardcoded') || combined.includes('password')) return 'Hardcoded Credentials';
  if (combined.includes('md5') || combined.includes('sha1') || combined.includes('random')) return 'Weak Cryptography';
  if (combined.includes('ssl') || combined.includes('tls') || combined.includes('verify')) return 'Insecure Transport';
  if (combined.includes('exec') || combined.includes('eval')) return 'Code Injection';
  return 'Security Misconfiguration';
}

export const banditAdapter: ScannerAdapter = {
  name: 'bandit',

  async checkHealth(): Promise<ScannerHealth> {
    const bin = getBanditBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['--version'],
      cwd: process.cwd(),
      timeoutMs: 5000,
    });

    const available = !res.spawnError && res.exitCode === 0;
    const versionMatch = `${res.stdout} ${res.stderr}`.match(/bandit\s+([0-9.]+)/i);

    return {
      name: 'bandit',
      displayName: 'Bandit (Python SAST)',
      description: 'Official PyCQA static security analyzer for Python AST.',
      supportedLanguages: ['Python'],
      available,
      version: available ? versionMatch?.[1] || res.stdout.trim().split('\n')[0] || 'installed' : null,
      executablePath: bin,
      installInstructionsWindows: BANDIT_INSTALL_WIN,
      installInstructionsLinux: BANDIT_INSTALL_LINUX,
      checkedAt: new Date().toISOString(),
      error: available ? null : res.spawnError || res.stderr || 'Bandit executable not found on PATH.',
    };
  },

  async scan(targetDir, { timeoutMs, signal }): Promise<ScannerAdapterResult> {
    const health = await this.checkHealth();
    if (!health.available) {
      return {
        scannerName: 'bandit',
        available: false,
        version: null,
        status: 'unavailable',
        durationMs: 0,
        findings: [],
        diagnostics: [],
        errorMessage: 'Bandit is not installed or not found on PATH.',
        installHint: BANDIT_INSTALL_WIN,
      };
    }

    const pyFiles = collectDirectoryFiles(targetDir).filter((f) => f.toLowerCase().endsWith('.py'));
    if (pyFiles.length === 0) {
      return {
        scannerName: 'bandit',
        available: true,
        version: health.version,
        status: 'completed',
        durationMs: 0,
        findings: [],
        diagnostics: [],
      };
    }

    const bin = getBanditBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['-r', '.', '-f', 'json', '-q'],
      cwd: targetDir,
      timeoutMs,
      signal,
    });

    if (res.cancelled) {
      return {
        scannerName: 'bandit',
        available: true,
        version: health.version,
        status: 'cancelled',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: 'Bandit scan cancelled.',
      };
    }

    if (res.timedOut) {
      return {
        scannerName: 'bandit',
        available: true,
        version: health.version,
        status: 'timed_out',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: `Bandit timed out after ${timeoutMs}ms.`,
      };
    }

    // Bandit exits 0 (no issues) or 1 (issues found)
    if (res.exitCode !== 0 && res.exitCode !== 1) {
      return {
        scannerName: 'bandit',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: res.stderr || `Bandit exited with code ${res.exitCode}`,
      };
    }

    try {
      const findings = parseBanditOutput(res.stdout, targetDir);
      const diagnostics = parseBanditDiagnostics(res.stdout, targetDir);
      // Enrich missing code snippets safely if needed
      for (const f of findings) {
        if (!f.codeSnippet) {
          const abs = path.join(targetDir, f.filePath);
          if (fs.existsSync(abs)) {
            const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
            f.codeSnippet = redactTextSecrets(
              lines.slice(Math.max(0, f.startLine - 2), (f.endLine || f.startLine) + 2).join('\n')
            );
          }
        }
      }
      return {
        scannerName: 'bandit',
        available: true,
        version: health.version,
        status: 'completed',
        durationMs: res.durationMs,
        findings,
        diagnostics,
      };
    } catch (err) {
      return {
        scannerName: 'bandit',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: `Failed to parse Bandit JSON output: ${err instanceof Error ? err.message : 'Unknown error'}`,
      };
    }
  },
};
