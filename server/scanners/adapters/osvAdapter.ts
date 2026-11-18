import path from 'node:path';
import type { ScannerHealth, Severity } from '../../../shared/types.ts';
import type { RawScannerFinding } from '../normalization/normalizer.ts';
import { collectDirectoryFiles } from '../security/fileSecurity.ts';
import type { ScannerAdapter, ScannerAdapterResult } from './customAdapter.ts';
import { runSafeProcess } from './processRunner.ts';

function getOsvBinary(): string {
  return process.env.OSV_SCANNER_PATH || 'osv-scanner';
}

const OSV_INSTALL_WIN = 'winget install Google.OSVScanner  # or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest';
const OSV_INSTALL_LINUX = 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest';

const SUPPORTED_MANIFESTS = new Set([
  'requirements.txt',
  'pyproject.toml',
  'pipfile.lock',
  'poetry.lock',
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'cargo.toml',
  'cargo.lock',
  'go.mod',
  'go.sum',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'gemfile.lock',
]);

interface OsvJsonReport {
  results?: Array<{
    source?: { path?: string; type?: string };
    packages?: Array<{
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: Array<{
        id?: string;
        aliases?: string[];
        summary?: string;
        details?: string;
        severity?: Array<{ type?: string; score?: string }>;
        database_specific?: { severity?: string };
        affected?: Array<{
          ranges?: Array<{
            events?: Array<{ introduced?: string; fixed?: string }>;
          }>;
        }>;
        references?: Array<{ url?: string }>;
      }>;
    }>;
  }>;
}

export function parseOsvOutput(stdout: string, targetDir: string): RawScannerFinding[] {
  if (!stdout.trim()) return [];
  const parsed = JSON.parse(stdout) as OsvJsonReport;
  const results = parsed.results || [];
  const findings: RawScannerFinding[] = [];
  const normalizedRoot = path.resolve(targetDir);

  for (const res of results) {
    const rawPath = res.source?.path || 'dependency-manifest';
    const relPath = path.isAbsolute(rawPath)
      ? path.relative(normalizedRoot, rawPath).replace(/\\/g, '/')
      : rawPath.replace(/\\/g, '/');

    for (const pkgEntry of res.packages || []) {
      const pkgName = pkgEntry.package?.name || 'unknown-package';
      const pkgVersion = pkgEntry.package?.version || 'unknown';
      const ecosystem = pkgEntry.package?.ecosystem || 'Dependency';

      for (const vuln of pkgEntry.vulnerabilities || []) {
        const vulnId = vuln.id || 'OSV-UNKNOWN';
        const cve = vuln.aliases?.find((a) => a.startsWith('CVE-')) || vulnId;
        const dbSev = (vuln.database_specific?.severity || '').toUpperCase();
        const severity: Severity =
          dbSev === 'CRITICAL'
            ? 'Critical'
            : dbSev === 'HIGH'
              ? 'High'
              : dbSev === 'MODERATE' || dbSev === 'MEDIUM'
                ? 'Medium'
                : dbSev === 'LOW'
                  ? 'Low'
                  : 'Medium';

        const fixedVersions: string[] = [];
        for (const aff of vuln.affected || []) {
          for (const range of aff.ranges || []) {
            for (const ev of range.events || []) {
              if (ev.fixed) fixedVersions.push(ev.fixed);
            }
          }
        }
        const fixHint =
          fixedVersions.length > 0
            ? `Upgrade ${pkgName} from ${pkgVersion} to fixed version: ${Array.from(new Set(fixedVersions)).join(', ')}.`
            : `Review ${pkgName}@${pkgVersion} advisory (${cve}) and upgrade or mitigate.`;

        findings.push({
          scannerName: 'osv',
          detectionSource: 'dependency_advisory',
          ruleId: cve,
          title: `Vulnerable Dependency: ${pkgName}@${pkgVersion} (${cve})`,
          description: vuln.summary || vuln.details || `Known vulnerability ${cve} affects ${pkgName}@${pkgVersion} (${ecosystem}).`,
          category: 'Vulnerable Dependency',
          severity,
          confidence: 'High',
          cweId: 'CWE-1395',
          owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
          filePath: relPath,
          startLine: 1,
          endLine: 1,
          language: ecosystem,
          codeSnippet: `${pkgName}==${pkgVersion} (${ecosystem})`,
          redactedEvidence: fixedVersions.length > 0 ? `Fixed in: ${fixedVersions.join(', ')}` : null,
          recommendation: fixHint,
          references: (vuln.references || []).map((r) => r.url).filter((u): u is string => Boolean(u)).slice(0, 4),
        });
      }
    }
  }

  return findings;
}

export const osvAdapter: ScannerAdapter = {
  name: 'osv',

  async checkHealth(): Promise<ScannerHealth> {
    const bin = getOsvBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['--version'],
      cwd: process.cwd(),
      timeoutMs: 5000,
    });

    const available = !res.spawnError && res.exitCode === 0;
    const version = available ? res.stdout.trim().split('\n')[0] || 'installed' : null;

    return {
      name: 'osv',
      displayName: 'OSV-Scanner (Dependency SCA)',
      description: 'Audits package manifests & lockfiles against the Open Source Vulnerabilities database.',
      supportedLanguages: [
        'requirements.txt',
        'pyproject.toml',
        'Pipfile.lock',
        'poetry.lock',
        'package.json',
        'package-lock.json',
        'pnpm-lock.yaml',
        'yarn.lock',
        'Cargo.toml',
        'Cargo.lock',
        'go.mod',
        'go.sum',
        'pom.xml',
        'build.gradle',
        'build.gradle.kts',
        'Gemfile.lock',
      ],
      available,
      version,
      executablePath: bin,
      installInstructionsWindows: OSV_INSTALL_WIN,
      installInstructionsLinux: OSV_INSTALL_LINUX,
      checkedAt: new Date().toISOString(),
      error: available ? null : res.spawnError || res.stderr || 'osv-scanner executable not found on PATH.',
    };
  },

  async scan(targetDir, { timeoutMs, signal }): Promise<ScannerAdapterResult> {
    const health = await this.checkHealth();
    if (!health.available) {
      return {
        scannerName: 'osv',
        available: false,
        version: null,
        status: 'unavailable',
        durationMs: 0,
        findings: [],
        errorMessage: 'OSV-Scanner is not installed or not found on PATH.',
        installHint: OSV_INSTALL_WIN,
      };
    }

    const manifests = collectDirectoryFiles(targetDir).filter((f) =>
      SUPPORTED_MANIFESTS.has(path.basename(f).toLowerCase())
    );
    if (manifests.length === 0) {
      return {
        scannerName: 'osv',
        available: true,
        version: health.version,
        status: 'completed',
        durationMs: 0,
        findings: [],
      };
    }

    const bin = getOsvBinary();
    const res = await runSafeProcess({
      command: bin,
      args: ['--format', 'json', '-r', '.'],
      cwd: targetDir,
      timeoutMs,
      signal,
    });

    if (res.cancelled) {
      return {
        scannerName: 'osv',
        available: true,
        version: health.version,
        status: 'cancelled',
        durationMs: res.durationMs,
        findings: [],
        errorMessage: 'OSV-Scanner cancelled.',
      };
    }

    if (res.timedOut) {
      return {
        scannerName: 'osv',
        available: true,
        version: health.version,
        status: 'timed_out',
        durationMs: res.durationMs,
        findings: [],
        errorMessage: `OSV-Scanner timed out after ${timeoutMs}ms.`,
      };
    }

    // osv-scanner exits 0 (no vulns) or 1 (vulns found)
    if (res.exitCode !== 0 && res.exitCode !== 1) {
      return {
        scannerName: 'osv',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: res.durationMs,
        findings: [],
        errorMessage: res.stderr || `osv-scanner exited with code ${res.exitCode}`,
      };
    }

    try {
      const findings = parseOsvOutput(res.stdout, targetDir);
      return {
        scannerName: 'osv',
        available: true,
        version: health.version,
        status: 'completed',
        durationMs: res.durationMs,
        findings,
      };
    } catch (err) {
      return {
        scannerName: 'osv',
        available: true,
        version: health.version,
        status: 'failed',
        durationMs: res.durationMs,
        findings: [],
        errorMessage: `Failed to parse OSV-Scanner JSON output: ${err instanceof Error ? err.message : 'Unknown error'}`,
      };
    }
  },
};
