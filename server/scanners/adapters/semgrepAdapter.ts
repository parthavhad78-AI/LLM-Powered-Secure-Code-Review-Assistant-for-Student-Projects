import fs from 'node:fs';
import path from 'node:path';
import type { ScannerHealth, Severity } from '../../../shared/types.ts';
import type { RawScanDiagnostic, RawScannerFinding } from '../normalization/normalizer.ts';
import { isAuthPlaceholderText, redactTextSecrets } from '../security/secretRedactor.ts';
import type { ScannerAdapter, ScannerAdapterResult } from './customAdapter.ts';
import { runSafeProcess } from './processRunner.ts';

function getSemgrepBinary(): string {
  return process.env.SEMGREP_PATH || 'semgrep';
}

const SEMGREP_INSTALL_WIN = 'pip install semgrep  # Note: On Windows, WSL2 or Docker is recommended for full Semgrep support';
const SEMGREP_INSTALL_LINUX = 'pip3 install semgrep';

interface SemgrepJsonResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      references?: string[];
      category?: string;
      confidence?: string;
    };
  };
}

interface SemgrepJsonError {
  type?: string;
  level?: string;
  message?: string;
  long_msg?: string;
  short_msg?: string;
  path?: string;
  spans?: Array<{
    file?: string;
    start?: { line?: number; col?: number };
  }>;
}

function toRelPath(rawFile: string, normalizedRoot: string): string {
  return path.isAbsolute(rawFile)
    ? path.relative(normalizedRoot, rawFile).replace(/\\/g, '/')
    : rawFile.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function parseSemgrepDiagnostics(stdout: string, targetDir: string): RawScanDiagnostic[] {
  if (!stdout.trim()) return [];
  const parsed = JSON.parse(stdout) as { errors?: SemgrepJsonError[] };
  const errors = parsed.errors || [];
  const normalizedRoot = path.resolve(targetDir);
  const diagnostics: RawScanDiagnostic[] = [];

  for (const err of errors) {
    const span = err.spans?.[0];
    const rawPath = span?.file || err.path;
    const msg = err.short_msg || err.message || err.long_msg || 'Semgrep parse diagnostic';
    if (!rawPath && !/syntax|parse/i.test(msg)) continue;
    diagnostics.push({
      scannerName: 'semgrep',
      filePath: rawPath ? toRelPath(rawPath, normalizedRoot) : 'project',
      line: Math.max(1, Number(span?.start?.line || 1)),
      column: span?.start?.col ? Number(span.start.col) : null,
      severity: String(err.level || '').toLowerCase() === 'warn' ? 'warning' : 'error',
      kind: /syntax/i.test(`${err.type || ''} ${msg}`) ? 'syntax_error' : 'parse_warning',
      message: redactTextSecrets(msg),
    });
  }
  return diagnostics;
}

export function parseSemgrepOutput(stdout: string, targetDir: string): RawScannerFinding[] {
  if (!stdout.trim()) return [];
  const parsed = JSON.parse(stdout) as { results?: SemgrepJsonResult[] };
  const results = parsed.results || [];
  const normalizedRoot = path.resolve(targetDir);

  return results.map((item) => {
    const relPath = toRelPath(item.path || 'unknown', normalizedRoot);

    const sevMap: Record<string, Severity> = {
      ERROR: 'High',
      WARNING: 'Medium',
      INFO: 'Low',
    };
    const severity = sevMap[(item.extra?.severity || '').toUpperCase()] || 'Medium';

    const cweRaw = item.extra?.metadata?.cwe;
    const cweStr = Array.isArray(cweRaw) ? cweRaw[0] : cweRaw;
    const cweId = cweStr ? cweStr.match(/CWE-\d+/i)?.[0]?.toUpperCase() || null : null;

    const owaspRaw = item.extra?.metadata?.owasp;
    const owaspCategory = Array.isArray(owaspRaw) ? owaspRaw[0] : owaspRaw || null;

    const ext = path.extname(relPath).toLowerCase();
    const language =
      ext === '.py'
        ? 'Python'
        : ext === '.ts' || ext === '.tsx'
          ? 'TypeScript'
          : ext === '.js' || ext === '.jsx'
            ? 'JavaScript'
            : 'Source';

    // CRITICAL FIX: Never accept Semgrep's "requires login" placeholder as source snippet
    const rawLines = item.extra?.lines || '';
    let safeSnippet = isAuthPlaceholderText(rawLines) ? '' : redactTextSecrets(rawLines);
    const startLine = item.start?.line || 1;
    const endLine = item.end?.line || startLine;

    if (!safeSnippet && relPath && relPath !== 'unknown') {
      const abs = path.resolve(normalizedRoot, relPath);
      if ((abs === normalizedRoot || abs.startsWith(`${normalizedRoot}${path.sep}`)) && fs.existsSync(abs)) {
        try {
          const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
          const s = Math.max(0, startLine - 3);
          const e = Math.min(lines.length, endLine + 2);
          safeSnippet = redactTextSecrets(
            lines.slice(s, e).map((l, idx) => `${s + idx + 1}: ${l}`).join('\n')
          );
        } catch {
          // Ignore file read failures during snippet hydration
        }
      }
    }

    const rawMessage = item.extra?.message || '';
    const description =
      rawMessage && !isAuthPlaceholderText(rawMessage)
        ? redactTextSecrets(rawMessage)
        : 'Semgrep security rule matched.';

    return {
      scannerName: 'semgrep',
      detectionSource: 'confirmed_tool',
      ruleId: item.check_id || 'SEMGREP-RULE',
      title: `Semgrep: ${(item.check_id || 'Security Rule').split('.').pop()?.replace(/-/g, ' ') || 'Finding'}`,
      description,
      category: item.extra?.metadata?.category || 'Security Misconfiguration',
      severity,
      confidence: (item.extra?.metadata?.confidence as 'High' | 'Medium' | 'Low') || 'Medium',
      cweId,
      owaspCategory,
      filePath: relPath,
      startLine,
      endLine,
      startCol: item.start?.col ?? null,
      endCol: item.end?.col ?? null,
      language,
      codeSnippet: safeSnippet,
      recommendation: description,
      references: item.extra?.metadata?.references || [],
    };
  });
}

export const semgrepAdapter: ScannerAdapter = {
  name: 'semgrep',

  async checkHealth(): Promise<ScannerHealth> {
    const bin = getSemgrepBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['--version'],
      cwd: process.cwd(),
      timeoutMs: 6000,
    });

    const available = !res.spawnError && res.exitCode === 0;
    const version = available ? res.stdout.trim().split('\n')[0] || 'installed' : null;

    return {
      name: 'semgrep',
      displayName: 'Semgrep (Multi-Language SAST)',
      description: 'Semantic static analysis for Python, JavaScript, and TypeScript.',
      supportedLanguages: ['Python', 'JavaScript', 'TypeScript'],
      available,
      version,
      executablePath: bin,
      installInstructionsWindows: SEMGREP_INSTALL_WIN,
      installInstructionsLinux: SEMGREP_INSTALL_LINUX,
      checkedAt: new Date().toISOString(),
      error: available ? null : res.spawnError || res.stderr || 'Semgrep executable not found on PATH.',
    };
  },

  async scan(targetDir, { timeoutMs, signal }): Promise<ScannerAdapterResult> {
    const health = await this.checkHealth();
    if (!health.available) {
      return {
        scannerName: 'semgrep',
        available: false,
        version: null,
        status: 'unavailable',
        durationMs: 0,
        findings: [],
        diagnostics: [],
        errorMessage: 'Semgrep is not installed or not found on PATH.',
        installHint: SEMGREP_INSTALL_WIN,
      };
    }

    const bin = getSemgrepBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['scan', '--config', 'auto', '--json', '--quiet', '--no-git-ignore', '.'],
      cwd: targetDir,
      timeoutMs,
      signal,
    });

    if (res.cancelled) {
      return {
        scannerName: 'semgrep',
        available: true,
        version: health.version,
        status: 'cancelled',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: 'Semgrep scan cancelled.',
      };
    }

    if (res.timedOut) {
      return {
        scannerName: 'semgrep',
        available: true,
        version: health.version,
        status: 'timed_out',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: `Semgrep timed out after ${timeoutMs}ms.`,
      };
    }

    if (res.exitCode !== 0 && res.exitCode !== 1) {
      return {
        scannerName: 'semgrep',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: res.stderr || `Semgrep exited with code ${res.exitCode}`,
      };
    }

    try {
      const findings = parseSemgrepOutput(res.stdout, targetDir);
      const diagnostics = parseSemgrepDiagnostics(res.stdout, targetDir);

      // Hydrate snippets directly from the real scanned file on disk when Semgrep omits or withholds lines
      for (const f of findings) {
        if (!f.codeSnippet) {
          const abs = path.join(targetDir, f.filePath);
          if (fs.existsSync(abs)) {
            const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
            const s = Math.max(0, f.startLine - 3);
            const e = Math.min(lines.length, (f.endLine || f.startLine) + 2);
            f.codeSnippet = redactTextSecrets(
              lines.slice(s, e).map((l, idx) => `${s + idx + 1}: ${l}`).join('\n')
            );
          }
        }
      }
      return {
        scannerName: 'semgrep',
        available: true,
        version: health.version,
        status: 'completed',
        durationMs: res.durationMs,
        findings,
        diagnostics,
      };
    } catch (err) {
      return {
        scannerName: 'semgrep',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: res.durationMs,
        findings: [],
        diagnostics: [],
        errorMessage: `Failed to parse Semgrep JSON output: ${err instanceof Error ? err.message : 'Unknown error'}`,
      };
    }
  },
};
