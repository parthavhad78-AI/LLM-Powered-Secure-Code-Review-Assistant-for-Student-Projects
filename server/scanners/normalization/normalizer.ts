import crypto from 'node:crypto';
import type {
  ConfidenceLevel,
  ContributingScannerEvidence,
  DetectionSource,
  DiagnosticScannerMessage,
  Severity,
} from '../../../shared/types.ts';
import {
  isAuthPlaceholderText,
  redactTextSecrets,
  sanitizeScannerSnippet,
} from '../security/secretRedactor.ts';

export interface RawScanDiagnostic {
  scannerName: 'custom' | 'bandit' | 'semgrep' | 'gitleaks' | 'eslint' | 'osv';
  filePath: string;
  line: number;
  column?: number | null;
  unlocated?: boolean;
  severity: 'error' | 'warning';
  kind: 'syntax_error' | 'parse_warning';
  message: string;
}

export interface NormalizedDiagnostic {
  canonicalKey: string;
  scannerName: string;
  contributingScanners: string[];
  scannerMessages: DiagnosticScannerMessage[];
  filePath: string;
  line: number;
  column: number | null;
  severity: 'error' | 'warning';
  kind: 'syntax_error' | 'parse_warning';
  message: string;
}

export interface RawScannerFinding {
  scannerName: 'custom' | 'bandit' | 'semgrep' | 'gitleaks' | 'eslint' | 'osv';
  detectionSource: DetectionSource;
  ruleId: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  cweId?: string | null;
  owaspCategory?: string | null;
  filePath: string;
  startLine: number;
  endLine?: number;
  startCol?: number | null;
  endCol?: number | null;
  language: string;
  codeSnippet?: string;
  redactedEvidence?: string | null;
  recommendation?: string;
  references?: string[];
}

export interface NormalizedFinding {
  fingerprint: string;
  canonicalKey: string;
  projectId: string;
  scannerName: string;
  detectionSource: DetectionSource;
  ruleId: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  cweId: string | null;
  owaspCategory: string | null;
  filePath: string;
  startLine: number;
  endLine: number;
  startCol: number | null;
  endCol: number | null;
  language: string;
  codeSnippet: string;
  redactedEvidence: string | null;
  recommendation: string;
  references: string[];
  contributingScanners: string[];
  scannerEvidence: ContributingScannerEvidence[];
}

const CATEGORY_OWASP_MAP: Record<string, { cwe: string; owasp: string }> = {
  'SQL Injection': { cwe: 'CWE-89', owasp: 'A03:2021 - Injection' },
  'Command Injection': { cwe: 'CWE-78', owasp: 'A03:2021 - Injection' },
  'Code Injection': { cwe: 'CWE-94', owasp: 'A03:2021 - Injection' },
  'Cross-Site Scripting': { cwe: 'CWE-79', owasp: 'A03:2021 - Injection' },
  'Hardcoded Credentials': { cwe: 'CWE-798', owasp: 'A07:2021 - Identification and Authentication Failures' },
  'Exposed Secrets': { cwe: 'CWE-798', owasp: 'A07:2021 - Identification and Authentication Failures' },
  'Plaintext Password Storage': { cwe: 'CWE-256', owasp: 'A02:2021 - Cryptographic Failures' },
  'Broken Authorization': { cwe: 'CWE-862', owasp: 'A01:2021 - Broken Access Control' },
  'Broken Authentication': { cwe: 'CWE-287', owasp: 'A07:2021 - Identification and Authentication Failures' },
  'Insecure Deserialization': { cwe: 'CWE-502', owasp: 'A08:2021 - Software and Data Integrity Failures' },
  'Weak Cryptography': { cwe: 'CWE-327', owasp: 'A02:2021 - Cryptographic Failures' },
  'Insecure Transport': { cwe: 'CWE-295', owasp: 'A02:2021 - Cryptographic Failures' },
  'Path Traversal': { cwe: 'CWE-22', owasp: 'A01:2021 - Broken Access Control' },
  'Security Misconfiguration': { cwe: 'CWE-16', owasp: 'A05:2021 - Security Misconfiguration' },
  'Open Redirect': { cwe: 'CWE-601', owasp: 'A01:2021 - Broken Access Control' },
  'Vulnerable Dependency': { cwe: 'CWE-1395', owasp: 'A06:2021 - Vulnerable and Outdated Components' },
  'Error Handling': { cwe: 'CWE-390', owasp: 'A05:2021 - Security Misconfiguration' },
};

const CATEGORY_FAMILY_MAP: Record<string, string> = {
  'SQL Injection': 'SQLI',
  'Command Injection': 'CMDI',
  'Code Injection': 'CODE_INJ',
  'Cross-Site Scripting': 'XSS',
  'Hardcoded Credentials': 'CREDENTIALS_SECRETS',
  'Exposed Secrets': 'CREDENTIALS_SECRETS',
  'Plaintext Password Storage': 'PLAINTEXT_PWD',
  'Broken Authorization': 'AUTHZ',
  'Broken Access Control': 'AUTHZ',
  'Broken Authentication': 'AUTHN',
  'Insecure Deserialization': 'DESER',
  'Weak Cryptography': 'WEAK_CRYPTO',
  'Insecure Transport': 'TLS',
  'Path Traversal': 'PATH_TRAV',
  'Open Redirect': 'OPEN_REDIRECT',
  'Vulnerable Dependency': 'DEPENDENCY',
  'Error Handling': 'ERROR_HANDLING',
  'Security Misconfiguration': 'MISCONFIG',
};

const CWE_FAMILY_MAP: Record<string, string> = {
  'CWE-89': 'SQLI',
  'CWE-78': 'CMDI',
  'CWE-77': 'CMDI',
  'CWE-88': 'CMDI',
  'CWE-94': 'CODE_INJ',
  'CWE-95': 'CODE_INJ',
  'CWE-79': 'XSS',
  'CWE-798': 'CREDENTIALS_SECRETS',
  'CWE-259': 'CREDENTIALS_SECRETS',
  'CWE-321': 'CREDENTIALS_SECRETS',
  'CWE-256': 'PLAINTEXT_PWD',
  'CWE-257': 'PLAINTEXT_PWD',
  'CWE-312': 'PLAINTEXT_PWD',
  'CWE-862': 'AUTHZ',
  'CWE-863': 'AUTHZ',
  'CWE-639': 'AUTHZ',
  'CWE-284': 'AUTHZ',
  'CWE-285': 'AUTHZ',
  'CWE-287': 'AUTHN',
  'CWE-306': 'AUTHN',
  'CWE-502': 'DESER',
  'CWE-326': 'WEAK_CRYPTO',
  'CWE-327': 'WEAK_CRYPTO',
  'CWE-328': 'WEAK_CRYPTO',
  'CWE-330': 'WEAK_CRYPTO',
  'CWE-338': 'WEAK_CRYPTO',
  'CWE-916': 'WEAK_CRYPTO',
  'CWE-295': 'TLS',
  'CWE-22': 'PATH_TRAV',
  'CWE-601': 'OPEN_REDIRECT',
  'CWE-1395': 'DEPENDENCY',
  'CWE-390': 'ERROR_HANDLING',
};

export function normalizeRelativeFilePath(filePath: string): string {
  return filePath
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '');
}

export function getCanonicalFamily(finding: {
  category: string;
  cweId?: string | null;
  ruleId?: string;
  title?: string;
}): string {
  if (finding.cweId && CWE_FAMILY_MAP[finding.cweId.toUpperCase()]) {
    return CWE_FAMILY_MAP[finding.cweId.toUpperCase()];
  }
  const direct = CATEGORY_FAMILY_MAP[finding.category];
  if (direct && direct !== 'MISCONFIG') {
    return direct;
  }

  // Fallback inference for external tools that emit generic categories (e.g. Semgrep's "security")
  const hint = `${finding.category} ${finding.ruleId || ''} ${finding.title || ''}`.toLowerCase();
  if (/\bsqli\b|sql[-_ ]injection|formatted[-_ ]sql|hardcoded[-_ ]sql/.test(hint)) return 'SQLI';
  if (/subprocess|shell[-_ ]true|command[-_ ]injection|os[-_ ]system|child[-_ ]process/.test(hint)) return 'CMDI';
  if (/hardcoded[-_ ]?(password|secret|key|token)|secret[-_ ]detected|gitleaks|api[-_ ]key/.test(hint)) {
    return 'CREDENTIALS_SECRETS';
  }
  if (/plaintext[-_ ]password/.test(hint)) return 'PLAINTEXT_PWD';
  if (/\bmd5\b|\bsha1\b|weak[-_ ]hash|weak[-_ ]crypto|pseudo[-_ ]?random|math\.random/.test(hint)) {
    return 'WEAK_CRYPTO';
  }
  if (/pickle|yaml[-_ ]load|deserializ/.test(hint)) return 'DESER';
  if (/path[-_ ]travers|non[-_ ]literal[-_ ]fs/.test(hint)) return 'PATH_TRAV';
  if (/innerhtml|document\.write|\bxss\b|cross[-_ ]site[-_ ]scripting/.test(hint)) return 'XSS';
  if (/\beval\b|\bexec\b|code[-_ ]injection/.test(hint)) return 'CODE_INJ';
  if (/verify[-_ ]false|unverified[-_ ]ssl|insecure[-_ ]transport/.test(hint)) return 'TLS';
  if (/open[-_ ]redirect/.test(hint)) return 'OPEN_REDIRECT';
  if (/authz|authorization|access[-_ ]control/.test(hint)) return 'AUTHZ';

  return direct || finding.category.toUpperCase();
}

export function computeFindingCanonicalKey(
  projectId: string,
  finding: {
    filePath: string;
    category: string;
    cweId?: string | null;
    ruleId: string;
    title?: string;
    startLine: number;
    endLine: number;
  }
): string {
  const cleanFile = normalizeRelativeFilePath(finding.filePath);
  const family = getCanonicalFamily(finding);
  const startLine = Math.max(1, Math.floor(finding.startLine || 1));
  const endLine = Math.max(startLine, Math.floor(finding.endLine || startLine));

  // Dependency advisories & generic misconfigs without CWE discriminate by ruleId so distinct CVEs/configs never collapse
  const discriminator =
    family === 'DEPENDENCY' || (family === 'MISCONFIG' && !finding.cweId)
      ? finding.ruleId
      : 'canonical';

  return crypto
    .createHash('sha256')
    .update(`${projectId}::${cleanFile}::${family}::${startLine}-${endLine}::${discriminator}`)
    .digest('hex')
    .slice(0, 32);
}

export function mapSeverity(raw: string | number | undefined | null): Severity {
  if (typeof raw === 'number') {
    if (raw >= 2) return 'High';
    if (raw === 1) return 'Medium';
    return 'Low';
  }
  const s = String(raw || '').toLowerCase().trim();
  if (s === 'critical') return 'Critical';
  if (s === 'high' || s === 'error') return 'High';
  if (s === 'medium' || s === 'warning' || s === 'warn') return 'Medium';
  if (s === 'low') return 'Low';
  if (s === 'info' || s === 'informational' || s === 'note') return 'Informational';
  return 'Medium';
}

export function normalizeFinding(raw: RawScannerFinding, projectId: string): NormalizedFinding {
  const cleanFile = normalizeRelativeFilePath(raw.filePath);
  const startLine = Math.max(1, Math.floor(raw.startLine || 1));
  const endLine = Math.max(startLine, Math.floor(raw.endLine || startLine));
  const startCol =
    typeof raw.startCol === 'number' && Number.isFinite(raw.startCol) && raw.startCol >= 1
      ? Math.floor(raw.startCol)
      : null;
  const endCol =
    typeof raw.endCol === 'number' && Number.isFinite(raw.endCol) && raw.endCol >= 1
      ? Math.floor(raw.endCol)
      : null;

  const fallbackRefs = CATEGORY_OWASP_MAP[raw.category];
  const cweId = raw.cweId || fallbackRefs?.cwe || null;
  const owaspCategory = raw.owaspCategory || fallbackRefs?.owasp || 'A05:2021 - Security Misconfiguration';

  const safeSnippet = sanitizeScannerSnippet(raw.codeSnippet).slice(0, 1200);
  const safeEvidence =
    raw.redactedEvidence && !isAuthPlaceholderText(raw.redactedEvidence)
      ? redactTextSecrets(raw.redactedEvidence)
      : null;
  const safeDescription =
    raw.description && !isAuthPlaceholderText(raw.description)
      ? redactTextSecrets(raw.description)
      : 'Static analysis scanner flagged a security issue at this location.';

  const canonicalKey = computeFindingCanonicalKey(projectId, {
    filePath: cleanFile,
    category: raw.category,
    cweId,
    ruleId: raw.ruleId,
    title: raw.title,
    startLine,
    endLine,
  });

  const initialEvidence: ContributingScannerEvidence = {
    scannerName: raw.scannerName,
    ruleId: raw.ruleId,
    detectionSource: raw.detectionSource,
    title: raw.title,
    description: safeDescription,
    severity: raw.severity,
    confidence: raw.confidence,
    startLine,
    endLine,
    startCol,
    endCol,
    redactedEvidence: safeEvidence,
  };

  return {
    fingerprint: canonicalKey,
    canonicalKey,
    projectId,
    scannerName: raw.scannerName,
    detectionSource: raw.detectionSource,
    ruleId: raw.ruleId,
    title: raw.title,
    description: safeDescription,
    category: raw.category,
    severity: raw.severity,
    confidence: raw.confidence,
    cweId,
    owaspCategory,
    filePath: cleanFile,
    startLine,
    endLine,
    startCol,
    endCol,
    language: raw.language,
    codeSnippet: safeSnippet,
    redactedEvidence: safeEvidence,
    recommendation: raw.recommendation || 'Review the affected code and apply secure coding controls.',
    references: raw.references || [],
    contributingScanners: [raw.scannerName],
    scannerEvidence: [initialEvidence],
  };
}

const SOURCE_PRIORITY: Record<DetectionSource, number> = {
  confirmed_tool: 3,
  dependency_advisory: 3,
  pattern_based: 1,
};

const SEVERITY_PRIORITY: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
};

function rangesOverlap(aStart: number, aEnd: number, bStart: number, bEnd: number): boolean {
  return Math.max(aStart, bStart) <= Math.min(aEnd, bEnd);
}

function areCompatibleForDedupe(a: NormalizedFinding, b: NormalizedFinding): boolean {
  if (a.filePath !== b.filePath) return false;
  if (!rangesOverlap(a.startLine, a.endLine, b.startLine, b.endLine)) return false;

  // Dependency advisories on manifests are keyed by package/ruleId
  if (a.category === 'Vulnerable Dependency' || b.category === 'Vulnerable Dependency') {
    return a.category === b.category && a.ruleId === b.ruleId;
  }

  const famA = getCanonicalFamily(a);
  const famB = getCanonicalFamily(b);

  // Generic misconfig only merges if CWEs explicitly match or ruleId matches
  if (famA === 'MISCONFIG' && famB === 'MISCONFIG') {
    if (a.cweId && b.cweId) return a.cweId === b.cweId;
    return a.ruleId === b.ruleId;
  }

  // Allow same-family findings at overlapping lines to consolidate (including AST + pattern rules from same or different engines)
  return famA === famB || (Boolean(a.cweId && b.cweId) && a.cweId === b.cweId);
}

function mergeTwoFindings(a: NormalizedFinding, b: NormalizedFinding): NormalizedFinding {
  const scoreA = SOURCE_PRIORITY[a.detectionSource] * 10 + SEVERITY_PRIORITY[a.severity];
  const scoreB = SOURCE_PRIORITY[b.detectionSource] * 10 + SEVERITY_PRIORITY[b.severity];

  const primary = scoreB > scoreA ? b : a;
  const secondary = primary === b ? a : b;

  // Preserve highest severity across all contributing detections
  const highestSeverity =
    SEVERITY_PRIORITY[a.severity] >= SEVERITY_PRIORITY[b.severity] ? a.severity : b.severity;

  // Preserve widest/most complete line range & sharpest column coordinates when available
  const startLine = Math.min(a.startLine, b.startLine);
  const endLine = Math.max(a.endLine, b.endLine);

  let startCol = primary.startCol;
  let endCol = primary.endCol;
  if ((startCol === null || endCol === null) && secondary.startCol !== null && secondary.endCol !== null) {
    startCol = secondary.startCol;
    endCol = secondary.endCol;
  }

  const contributingScanners = Array.from(
    new Set([...a.contributingScanners, ...b.contributingScanners])
  ).sort();

  const seenEv = new Set<string>();
  const scannerEvidence: ContributingScannerEvidence[] = [];
  for (const ev of [...a.scannerEvidence, ...b.scannerEvidence]) {
    const key = `${ev.scannerName}::${ev.ruleId}::${ev.startLine}::${ev.endLine}`;
    if (!seenEv.has(key)) {
      seenEv.add(key);
      scannerEvidence.push(ev);
    }
  }

  const mergedRefs = Array.from(new Set([...primary.references, ...secondary.references]));
  const mergedCodeSnippet = primary.codeSnippet || secondary.codeSnippet;
  const mergedEvidence = primary.redactedEvidence || secondary.redactedEvidence || null;
  const cweId = primary.cweId || secondary.cweId;
  const owaspCategory = primary.owaspCategory || secondary.owaspCategory;

  const canonicalKey = computeFindingCanonicalKey(primary.projectId, {
    filePath: primary.filePath,
    category: primary.category,
    cweId,
    ruleId: primary.ruleId,
    title: primary.title,
    startLine,
    endLine,
  });

  return {
    ...primary,
    fingerprint: canonicalKey,
    canonicalKey,
    severity: highestSeverity,
    cweId,
    owaspCategory,
    startLine,
    endLine,
    startCol,
    endCol,
    codeSnippet: mergedCodeSnippet,
    redactedEvidence: mergedEvidence,
    references: mergedRefs,
    contributingScanners,
    scannerEvidence,
  };
}

export function deduplicateFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  // Deterministic ordering before clustering ensures order-independent repeatable output
  const sortedInput = [...findings].sort((a, b) => {
    if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
    if (a.startLine !== b.startLine) return a.startLine - b.startLine;
    if (b.endLine !== a.endLine) return b.endLine - a.endLine;
    const prioDiff =
      SOURCE_PRIORITY[b.detectionSource] * 10 +
      SEVERITY_PRIORITY[b.severity] -
      (SOURCE_PRIORITY[a.detectionSource] * 10 + SEVERITY_PRIORITY[a.severity]);
    if (prioDiff !== 0) return prioDiff;
    return `${a.scannerName}:${a.ruleId}`.localeCompare(`${b.scannerName}:${b.ruleId}`);
  });

  const merged: NormalizedFinding[] = [];
  for (const item of sortedInput) {
    const matchIndex = merged.findIndex((existing) => areCompatibleForDedupe(existing, item));
    if (matchIndex === -1) {
      merged.push(item);
    } else {
      merged[matchIndex] = mergeTwoFindings(merged[matchIndex], item);
    }
  }

  // Fixed-point transitive pass: if expanding a line range (e.g. 12..12 -> 12..13) bridges
  // two previously adjacent detections (e.g. 13..13), collapse them deterministically.
  let collapsed = true;
  while (collapsed) {
    collapsed = false;
    for (let i = 0; i < merged.length; i++) {
      for (let j = i + 1; j < merged.length; j++) {
        if (areCompatibleForDedupe(merged[i], merged[j])) {
          merged[i] = mergeTwoFindings(merged[i], merged[j]);
          merged.splice(j, 1);
          collapsed = true;
          break;
        }
      }
      if (collapsed) break;
    }
  }

  return merged.sort((a, b) => {
    const sevDiff = SEVERITY_PRIORITY[b.severity] - SEVERITY_PRIORITY[a.severity];
    if (sevDiff !== 0) return sevDiff;
    if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
    if (a.startLine !== b.startLine) return a.startLine - b.startLine;
    return a.canonicalKey.localeCompare(b.canonicalKey);
  });
}

export function computeDiagnosticCanonicalKey(
  filePath: string,
  kind: string,
  line: number
): string {
  const cleanFile = normalizeRelativeFilePath(filePath);
  return crypto
    .createHash('sha256')
    .update(`${cleanFile}::${kind}::${Math.max(1, line)}`)
    .digest('hex')
    .slice(0, 24);
}

interface InternalDiagnostic extends NormalizedDiagnostic {
  unlocated: boolean;
}

function canMergeDiagnostics(a: InternalDiagnostic, b: InternalDiagnostic): boolean {
  if (a.filePath !== b.filePath || a.kind !== b.kind) return false;
  // Unlocated syntax diagnostic (e.g. Bandit reporting file-level AST parse error without line)
  // merges into an existing located syntax diagnostic on the same file.
  if (a.unlocated || b.unlocated) return true;
  // Same syntax error reported at line 66 (unclosed '(') vs line 67 (EOF/next statement) by different parsers
  return Math.abs(a.line - b.line) <= 2;
}

export function deduplicateDiagnostics(diagnostics: RawScanDiagnostic[]): NormalizedDiagnostic[] {
  const items: InternalDiagnostic[] = [...diagnostics]
    .map((d) => {
      const cleanFile = normalizeRelativeFilePath(d.filePath);
      const line = Math.max(1, Math.floor(d.line || 1));
      const column = typeof d.column === 'number' && d.column >= 1 ? Math.floor(d.column) : null;
      return {
        canonicalKey: computeDiagnosticCanonicalKey(cleanFile, d.kind, line),
        scannerName: d.scannerName,
        contributingScanners: [d.scannerName],
        scannerMessages: [
          {
            scannerName: d.scannerName,
            message: d.message,
            line,
            column,
          },
        ],
        filePath: cleanFile,
        line,
        column,
        severity: d.severity,
        kind: d.kind,
        message: d.message,
        unlocated: Boolean(d.unlocated),
      };
    })
    // Prefer located diagnostics first so unlocated ones merge onto the exact line/col
    .sort((a, b) => {
      if (a.unlocated !== b.unlocated) return a.unlocated ? 1 : -1;
      if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
      return a.line - b.line;
    });

  const merged: InternalDiagnostic[] = [];
  for (const item of items) {
    const idx = merged.findIndex((existing) => canMergeDiagnostics(existing, item));
    if (idx === -1) {
      merged.push(item);
      continue;
    }

    const existing = merged[idx];
    const preferItemLoc = existing.unlocated && !item.unlocated;
    const bestLine = preferItemLoc
      ? item.line
      : !existing.unlocated && !item.unlocated
        ? Math.min(existing.line, item.line)
        : existing.line;
    const bestCol = preferItemLoc
      ? item.column
      : existing.column ?? item.column ?? null;
    const bestSeverity =
      existing.severity === 'error' || item.severity === 'error' ? 'error' : 'warning';

    const scanners = Array.from(
      new Set([...existing.contributingScanners, ...item.contributingScanners])
    ).sort();

    const seenMsg = new Set(
      existing.scannerMessages.map((m) => `${m.scannerName}::${m.message}`)
    );
    const scannerMessages = [...existing.scannerMessages];
    for (const m of item.scannerMessages) {
      const k = `${m.scannerName}::${m.message}`;
      if (!seenMsg.has(k)) {
        seenMsg.add(k);
        scannerMessages.push(m);
      }
    }

    const primaryMessage =
      existing.scannerName === 'custom'
        ? existing.message
        : item.scannerName === 'custom'
          ? item.message
          : existing.message;

    merged[idx] = {
      ...existing,
      canonicalKey: computeDiagnosticCanonicalKey(existing.filePath, existing.kind, bestLine),
      scannerName: existing.scannerName === 'custom' || item.scannerName !== 'custom' ? existing.scannerName : item.scannerName,
      contributingScanners: scanners,
      scannerMessages,
      line: bestLine,
      column: bestCol,
      severity: bestSeverity,
      message: primaryMessage,
      unlocated: existing.unlocated && item.unlocated,
    };
  }

  return merged
    .map(({ unlocated: _unlocated, ...rest }) => rest)
    .sort((a, b) => {
      if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
      return a.line - b.line;
    });
}
