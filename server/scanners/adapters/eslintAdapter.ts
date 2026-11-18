import { ESLint } from 'eslint';
import securityPlugin from 'eslint-plugin-security';
import fs from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import path from 'node:path';
import type { ScannerHealth, Severity } from '../../../shared/types.ts';
import type { RawScanDiagnostic, RawScannerFinding } from '../normalization/normalizer.ts';
import { collectDirectoryFiles } from '../security/fileSecurity.ts';
import type { ScannerAdapter, ScannerAdapterResult } from './customAdapter.ts';

const ESLINT_RULE_META: Record<string, { category: string; cweId: string; severity: Severity }> = {
  'security/detect-eval-with-expression': {
    category: 'Code Injection',
    cweId: 'CWE-95',
    severity: 'Critical',
  },
  'security/detect-child-process': {
    category: 'Command Injection',
    cweId: 'CWE-78',
    severity: 'High',
  },
  'security/detect-non-literal-fs-filename': {
    category: 'Path Traversal',
    cweId: 'CWE-22',
    severity: 'Medium',
  },
  'security/detect-non-literal-regexp': {
    category: 'Security Misconfiguration',
    cweId: 'CWE-1333',
    severity: 'Medium',
  },
  'security/detect-non-literal-require': {
    category: 'Code Injection',
    cweId: 'CWE-94',
    severity: 'High',
  },
  'security/detect-object-injection': {
    category: 'Security Misconfiguration',
    cweId: 'CWE-94',
    severity: 'Low',
  },
  'security/detect-unsafe-regex': {
    category: 'Security Misconfiguration',
    cweId: 'CWE-1333',
    severity: 'Medium',
  },
  'security/detect-pseudoRandomBytes': {
    category: 'Weak Cryptography',
    cweId: 'CWE-338',
    severity: 'High',
  },
  'security/detect-possible-timing-attacks': {
    category: 'Weak Cryptography',
    cweId: 'CWE-208',
    severity: 'Low',
  },
  'security/detect-buffer-noassert': {
    category: 'Security Misconfiguration',
    cweId: 'CWE-120',
    severity: 'Medium',
  },
};

export interface EslintLintResultLike {
  filePath: string;
  messages: Array<{
    ruleId: string | null;
    severity: number;
    message: string;
    line?: number;
    endLine?: number;
    column?: number;
    endColumn?: number;
    fatal?: boolean;
  }>;
}

export function parseEslintDiagnostics(
  results: EslintLintResultLike[],
  targetDir: string
): RawScanDiagnostic[] {
  const diagnostics: RawScanDiagnostic[] = [];
  const normalizedRoot = path.resolve(targetDir);

  for (const fileRes of results) {
    const relPath = path.isAbsolute(fileRes.filePath)
      ? path.relative(normalizedRoot, fileRes.filePath).replace(/\\/g, '/')
      : fileRes.filePath.replace(/\\/g, '/');

    for (const msg of fileRes.messages) {
      if (msg.fatal || (msg.ruleId === null && /parsing error/i.test(msg.message))) {
        diagnostics.push({
          scannerName: 'eslint',
          filePath: relPath,
          line: msg.line || 1,
          column: msg.column || null,
          severity: 'error',
          kind: 'syntax_error',
          message: msg.message,
        });
      }
    }
  }
  return diagnostics;
}

export function parseEslintResults(
  results: EslintLintResultLike[],
  targetDir: string
): RawScannerFinding[] {
  const findings: RawScannerFinding[] = [];
  const normalizedRoot = path.resolve(targetDir);

  for (const fileRes of results) {
    const relPath = path.isAbsolute(fileRes.filePath)
      ? path.relative(normalizedRoot, fileRes.filePath).replace(/\\/g, '/')
      : fileRes.filePath.replace(/\\/g, '/');

    const ext = path.extname(relPath).toLowerCase();
    const language = ext === '.ts' || ext === '.tsx' ? 'TypeScript' : 'JavaScript';

    let fileLines: string[] = [];
    try {
      if (fs.existsSync(fileRes.filePath)) {
        fileLines = fs.readFileSync(fileRes.filePath, 'utf8').split(/\r?\n/);
      }
    } catch {
      fileLines = [];
    }

    for (const msg of fileRes.messages) {
      if (!msg.ruleId || !msg.ruleId.startsWith('security/')) {
        continue;
      }

      const meta = ESLINT_RULE_META[msg.ruleId] || {
        category: 'Security Misconfiguration',
        cweId: 'CWE-16',
        severity: msg.severity >= 2 ? ('High' as Severity) : ('Medium' as Severity),
      };

      const startLine = msg.line || 1;
      const endLine = msg.endLine || startLine;
      const snippet =
        fileLines.length > 0
          ? fileLines.slice(Math.max(0, startLine - 2), startLine + 2).join('\n')
          : '';

      findings.push({
        scannerName: 'eslint',
        detectionSource: 'confirmed_tool',
        ruleId: msg.ruleId,
        title: `ESLint Security: ${msg.ruleId.replace('security/', '').replace(/-/g, ' ')}`,
        description: msg.message,
        category: meta.category,
        severity: meta.severity,
        confidence: meta.severity === 'Low' ? 'Low' : 'Medium',
        cweId: meta.cweId,
        filePath: relPath,
        startLine,
        endLine,
        startCol: msg.column ?? null,
        endCol: msg.endColumn ?? null,
        language,
        codeSnippet: snippet,
        recommendation: 'Review the ESLint security plugin warning and replace unsafe dynamic patterns with validated alternatives.',
        references: ['https://github.com/eslint-community/eslint-plugin-security'],
      });
    }
  }

  return findings;
}

export const eslintAdapter: ScannerAdapter = {
  name: 'eslint',

  async checkHealth(): Promise<ScannerHealth> {
    return {
      name: 'eslint',
      displayName: 'ESLint + eslint-plugin-security',
      description: 'Isolated JavaScript & TypeScript security linter using controlled flat config.',
      supportedLanguages: ['JavaScript', 'TypeScript'],
      available: true,
      version: ESLint.version || 'installed',
      executablePath: 'embedded-eslint-api',
      installInstructionsWindows: 'npm install eslint eslint-plugin-security',
      installInstructionsLinux: 'npm install eslint eslint-plugin-security',
      checkedAt: new Date().toISOString(),
    };
  },

  async scan(targetDir, { timeoutMs, signal }): Promise<ScannerAdapterResult> {
    const start = Date.now();
    if (signal?.aborted) {
      return {
        scannerName: 'eslint',
        available: true,
        version: ESLint.version,
        status: 'cancelled',
        durationMs: 0,
        findings: [],
        errorMessage: 'ESLint scan cancelled.',
      };
    }

    const jsTsFiles = collectDirectoryFiles(targetDir).filter((f) =>
      /\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i.test(f)
    );

    if (jsTsFiles.length === 0) {
      return {
        scannerName: 'eslint',
        available: true,
        version: ESLint.version,
        status: 'completed',
        durationMs: Date.now() - start,
        findings: [],
      };
    }

    try {
      const eslint = new ESLint({
        cwd: targetDir,
        overrideConfigFile: true,
        overrideConfig: [
          {
            files: ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
            languageOptions: {
              ecmaVersion: 'latest',
              sourceType: 'module',
              parserOptions: {
                ecmaFeatures: { jsx: true },
              },
            },
            plugins: {
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              security: securityPlugin as any,
            },
            rules: {
              ...(securityPlugin.configs?.recommended?.rules || {
                'security/detect-eval-with-expression': 'error',
                'security/detect-child-process': 'warn',
                'security/detect-non-literal-fs-filename': 'warn',
                'security/detect-non-literal-regexp': 'warn',
                'security/detect-non-literal-require': 'warn',
                'security/detect-object-injection': 'warn',
                'security/detect-unsafe-regex': 'warn',
                'security/detect-pseudoRandomBytes': 'warn',
                'security/detect-possible-timing-attacks': 'warn',
              }),
            },
          },
        ],
      });

      const lintAll = async (): Promise<EslintLintResultLike[]> => {
        const collected: EslintLintResultLike[] = [];
        for (const rel of jsTsFiles) {
          if (signal?.aborted) throw new Error('CANCELLED');
          const abs = path.join(targetDir, rel);
          let code = fs.readFileSync(abs, 'utf8');
          if (/\.(ts|tsx|mts|cts)$/i.test(rel)) {
            try {
              code = stripTypeScriptTypes(code, { mode: 'strip' });
            } catch {
              // Leave original text if TSX/syntax is non-strippable
            }
          }
          const res = await eslint.lintText(code, { filePath: abs });
          collected.push(...(res as unknown as EslintLintResultLike[]));
        }
        return collected;
      };

      const timeoutPromise = new Promise<never>((_resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`ESLint timed out after ${timeoutMs}ms`)), timeoutMs);
        signal?.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('CANCELLED'));
        });
      });

      const results = await Promise.race([lintAll(), timeoutPromise]);
      const findings = parseEslintResults(results, targetDir);
      const diagnostics = parseEslintDiagnostics(results, targetDir);

      return {
        scannerName: 'eslint',
        available: true,
        version: ESLint.version,
        status: 'completed',
        durationMs: Date.now() - start,
        findings,
        diagnostics,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'ESLint execution failed.';
      const isCancelled = msg === 'CANCELLED';
      const isTimeout = msg.includes('timed out');
      return {
        scannerName: 'eslint',
        available: true,
        version: ESLint.version,
        status: isCancelled ? 'cancelled' : isTimeout ? 'timed_out' : 'failed',
        durationMs: Date.now() - start,
        findings: [],
        errorMessage: isCancelled ? 'ESLint scan cancelled.' : msg,
      };
    }
  },
};
