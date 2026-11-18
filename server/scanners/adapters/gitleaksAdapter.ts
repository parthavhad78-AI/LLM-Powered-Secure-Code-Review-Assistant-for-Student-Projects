import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { ScannerHealth } from '../../../shared/types.ts';
import type { RawScannerFinding } from '../normalization/normalizer.ts';
import { redactSecretValue } from '../security/secretRedactor.ts';
import type { ScannerAdapter, ScannerAdapterResult } from './customAdapter.ts';
import { runSafeProcess } from './processRunner.ts';

function getGitleaksBinary(): string {
  return process.env.GITLEAKS_PATH || 'gitleaks';
}

const GITLEAKS_INSTALL_WIN = 'winget install Gitleaks.Gitleaks  # or: choco install gitleaks';
const GITLEAKS_INSTALL_LINUX = 'brew install gitleaks  # or download binary from gitleaks releases';

interface GitleaksJsonFinding {
  RuleID?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  File?: string;
  Match?: string;
  Secret?: string;
  Entropy?: number;
}

export function parseGitleaksOutput(jsonText: string, targetDir: string): RawScannerFinding[] {
  if (!jsonText.trim()) return [];
  const parsed = JSON.parse(jsonText) as GitleaksJsonFinding[];
  if (!Array.isArray(parsed)) return [];
  const normalizedRoot = path.resolve(targetDir);

  return parsed.map((item) => {
    const rawFile = item.File || 'unknown';
    const relPath = path.isAbsolute(rawFile)
      ? path.relative(normalizedRoot, rawFile).replace(/\\/g, '/')
      : rawFile.replace(/\\/g, '/').replace(/^\.\//, '');

    const redactedSecret = redactSecretValue(item.Secret || item.Match || 'secret');
    const redactedMatch = item.Match
      ? item.Match.replace(item.Secret || '', redactedSecret)
      : redactedSecret;

    return {
      scannerName: 'gitleaks',
      detectionSource: 'confirmed_tool',
      ruleId: item.RuleID || 'GITLEAKS-SECRET',
      title: `Exposed Secret: ${item.Description || item.RuleID || 'Credential'}`,
      description: `Gitleaks detected a potential exposed secret (${item.RuleID || 'secret'}). The raw secret value has been redacted.`,
      category: 'Exposed Secrets',
      severity: 'Critical',
      confidence: 'High',
      cweId: 'CWE-798',
      owaspCategory: 'A07:2021 - Identification and Authentication Failures',
      filePath: relPath,
      startLine: item.StartLine || 1,
      endLine: item.EndLine || item.StartLine || 1,
      language: 'Secret / Config',
      codeSnippet: `Redacted match: ${redactedMatch}`,
      redactedEvidence: redactedSecret,
      recommendation: 'Revoke and rotate the exposed credential immediately, and store secrets in environment variables or a secret manager.',
      references: ['https://cwe.mitre.org/data/definitions/798.html'],
    };
  });
}

export const gitleaksAdapter: ScannerAdapter = {
  name: 'gitleaks',

  async checkHealth(): Promise<ScannerHealth> {
    const bin = getGitleaksBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['version'],
      cwd: process.cwd(),
      timeoutMs: 5000,
    });

    const available = !res.spawnError && res.exitCode === 0;
    const version = available ? res.stdout.trim().split('\n')[0] || 'installed' : null;

    return {
      name: 'gitleaks',
      displayName: 'Gitleaks (Secret Detection)',
      description: 'Dedicated credential and API key scanner across project files.',
      supportedLanguages: ['All Text & Source Files'],
      available,
      version,
      executablePath: bin,
      installInstructionsWindows: GITLEAKS_INSTALL_WIN,
      installInstructionsLinux: GITLEAKS_INSTALL_LINUX,
      checkedAt: new Date().toISOString(),
      error: available ? null : res.spawnError || res.stderr || 'Gitleaks executable not found on PATH.',
    };
  },

  async scan(targetDir, { timeoutMs, signal }): Promise<ScannerAdapterResult> {
    const health = await this.checkHealth();
    if (!health.available) {
      return {
        scannerName: 'gitleaks',
        available: false,
        version: null,
        status: 'unavailable',
        durationMs: 0,
        findings: [],
        errorMessage: 'Gitleaks is not installed or not found on PATH.',
        installHint: GITLEAKS_INSTALL_WIN,
      };
    }

    const reportPath = path.join(os.tmpdir(), `sl_gitleaks_${Date.now()}_${Math.random().toString(36).slice(2)}.json`);
    const bin = getGitleaksBinary();

    try {
      const res = await runSafeProcess({
        command: bin,
        args: ['detect', '--source', '.', '--no-git', '--report-format', 'json', '--report-path', reportPath],
        cwd: targetDir,
        timeoutMs,
        signal,
      });

      if (res.cancelled) {
        return {
          scannerName: 'gitleaks',
          available: true,
          version: health.version,
          status: 'cancelled',
          durationMs: res.durationMs,
          findings: [],
          errorMessage: 'Gitleaks scan cancelled.',
        };
      }

      if (res.timedOut) {
        return {
          scannerName: 'gitleaks',
          available: true,
          version: health.version,
          status: 'timed_out',
          durationMs: res.durationMs,
          findings: [],
          errorMessage: `Gitleaks timed out after ${timeoutMs}ms.`,
        };
      }

      // Gitleaks exits 0 (clean) or 1 (leaks found)
      if (res.exitCode !== 0 && res.exitCode !== 1) {
        return {
          scannerName: 'gitleaks',
          available: true,
          version: health.version,
          status: 'failed',
          durationMs: res.durationMs,
          findings: [],
          errorMessage: res.stderr || `Gitleaks exited with code ${res.exitCode}`,
        };
      }

      const jsonText = fs.existsSync(reportPath) ? fs.readFileSync(reportPath, 'utf8') : '[]';
      const findings = parseGitleaksOutput(jsonText, targetDir);

      return {
        scannerName: 'gitleaks',
        available: true,
        version: health.version,
        status: 'completed',
        durationMs: res.durationMs,
        findings,
      };
    } catch (err) {
      return {
        scannerName: 'gitleaks',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: 0,
        findings: [],
        errorMessage: `Failed to parse Gitleaks report: ${err instanceof Error ? err.message : 'Unknown error'}`,
      };
    } finally {
      try {
        if (fs.existsSync(reportPath)) fs.unlinkSync(reportPath);
      } catch {
        // Ignore cleanup failure
      }
    }
  },
};
