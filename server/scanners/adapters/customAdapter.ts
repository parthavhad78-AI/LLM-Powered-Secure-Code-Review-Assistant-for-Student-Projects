import type { ScannerHealth } from '../../../shared/types.ts';
import type { RawScanDiagnostic, RawScannerFinding } from '../normalization/normalizer.ts';
import { runCustomRulesOnDirectoryWithDiagnostics } from '../rules/customRules.ts';
import { collectDirectoryFiles } from '../security/fileSecurity.ts';

export interface ScannerAdapterResult {
  scannerName: 'custom' | 'bandit' | 'semgrep' | 'gitleaks' | 'eslint' | 'osv';
  available: boolean;
  version: string | null;
  status: 'completed' | 'failed' | 'unavailable' | 'timed_out' | 'cancelled';
  durationMs: number;
  findings: RawScannerFinding[];
  diagnostics?: RawScanDiagnostic[];
  errorMessage?: string | null;
  installHint?: string | null;
}

export interface ScannerAdapter {
  name: 'custom' | 'bandit' | 'semgrep' | 'gitleaks' | 'eslint' | 'osv';
  checkHealth(): Promise<ScannerHealth>;
  scan(targetDir: string, options: { timeoutMs: number; signal?: AbortSignal }): Promise<ScannerAdapterResult>;
}

export const customAdapter: ScannerAdapter = {
  name: 'custom',

  async checkHealth(): Promise<ScannerHealth> {
    return {
      name: 'custom',
      displayName: 'SecureLens AST & Deterministic Rules',
      description: 'Built-in TypeScript/Python AST and pattern security analyzer.',
      supportedLanguages: ['Python', 'JavaScript', 'TypeScript', 'Config'],
      available: true,
      version: '1.1.0-ast',
      executablePath: 'built-in',
      installInstructionsWindows: 'Built-in analyzer; no installation required.',
      installInstructionsLinux: 'Built-in analyzer; no installation required.',
      checkedAt: new Date().toISOString(),
    };
  },

  async scan(targetDir, { signal }): Promise<ScannerAdapterResult> {
    const start = Date.now();
    if (signal?.aborted) {
      return {
        scannerName: 'custom',
        available: true,
        version: '1.1.0-ast',
        status: 'cancelled',
        durationMs: 0,
        findings: [],
        diagnostics: [],
        errorMessage: 'Scan cancelled by student.',
      };
    }

    try {
      const files = collectDirectoryFiles(targetDir);
      const { findings, diagnostics } = await runCustomRulesOnDirectoryWithDiagnostics(
        targetDir,
        files,
        signal
      );
      return {
        scannerName: 'custom',
        available: true,
        version: '1.1.0-ast',
        status: signal?.aborted ? 'cancelled' : 'completed',
        durationMs: Date.now() - start,
        findings,
        diagnostics,
      };
    } catch (err) {
      return {
        scannerName: 'custom',
        available: true,
        version: '1.1.0-ast',
        status: 'failed',
        durationMs: Date.now() - start,
        findings: [],
        diagnostics: [],
        errorMessage: err instanceof Error ? err.message : 'Custom scanner execution failed.',
      };
    }
  },
};
