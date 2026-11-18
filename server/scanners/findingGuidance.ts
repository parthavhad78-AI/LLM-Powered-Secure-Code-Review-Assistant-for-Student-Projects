import type {
  FindingGuidance,
  SourceContext,
  SourceContextLine,
} from '../../shared/types.ts';
import { getDb } from '../database/db.ts';
import { sanitizeRelativePath } from './security/fileSecurity.ts';
import {
  redactLineWithColumns,
  redactTextSecrets,
} from './security/secretRedactor.ts';

const GUIDANCE_BY_CATEGORY: Record<string, FindingGuidance> = {
  'SQL Injection': {
    whyVulnerable:
      'SQL statements are assembled by concatenating or interpolating variables directly into the query string. The database cannot separate SQL syntax from user-supplied text, so special characters like quotes or SQL keywords can alter query logic.',
    potentialImpact:
      'Attackers can bypass authentication, read unauthorized records across tables, modify or delete database rows, and in some configurations execute administrative database commands.',
    recommendedApproach:
      'Use parameterized queries (prepared statements) with bound placeholders (?, %s, or $1) so the database driver treats user input strictly as data rather than executable SQL.',
  },
  'Command Injection': {
    whyVulnerable:
      'An external OS command is invoked through a system shell (such as shell=True or os.system) with potentially untrusted arguments. Shell interpreters evaluate metacharacters like ;, &&, |, and $().',
    potentialImpact:
      'If an attacker controls part of the command string, they can execute arbitrary operating system commands on the host with the application’s privileges.',
    recommendedApproach:
      'Invoke subprocess APIs with shell=False (or execFile/spawn in Node.js), pass the executable and arguments as an explicit list/array, and validate inputs against a strict allowlist.',
  },
  'Code Injection': {
    whyVulnerable:
      'Dynamic evaluation APIs (eval, exec, new Function) compile and execute arbitrary source strings at runtime.',
    potentialImpact:
      'Any attacker-controlled value reaching this sink leads to arbitrary code execution inside the application process, exposing secrets, files, and internal APIs.',
    recommendedApproach:
      'Replace dynamic evaluation with structured parsing (e.g., JSON.parse or ast.literal_eval) or an explicit dispatch table of allowed operations.',
  },
  'Weak Cryptography': {
    whyVulnerable:
      'Legacy algorithms such as MD5, SHA-1, or non-cryptographic PRNGs (Math.random) lack collision resistance or sufficient work factor for security-sensitive operations.',
    potentialImpact:
      'Weak password hashes can be cracked rapidly using precomputed tables or GPUs, and predictable tokens/random values can be guessed by attackers to hijack sessions.',
    recommendedApproach:
      'Use dedicated memory-hard password hashing algorithms (Argon2, bcrypt, or scrypt) with per-user salts, and use CSPRNG APIs (secrets in Python, crypto.randomBytes in Node.js) for tokens.',
  },
  'Hardcoded Credentials': {
    whyVulnerable:
      'A password, API key, or secret token appears to be stored directly as a literal string inside source code.',
    potentialImpact:
      'Anyone with read access to the source repository, build artifacts, or container image can extract the credential and gain unauthorized access to protected services or databases.',
    recommendedApproach:
      'Remove literal credentials from source code, rotate any exposed values, and load secrets at runtime via environment variables (os.environ / process.env) or a secret manager.',
  },
  'Exposed Secrets': {
    whyVulnerable:
      'Secret detection identified a credential or private key literal embedded in source or configuration files.',
    potentialImpact:
      'Exposed keys allow attackers to impersonate your application, access cloud resources, or exfiltrate private data.',
    recommendedApproach:
      'Revoke and rotate the exposed credential immediately, purge it from version history, and inject credentials exclusively through runtime environment configuration.',
  },
  'Plaintext Password Storage': {
    whyVulnerable:
      'Passwords are stored or persisted directly in plaintext (in memory, files, records, or database tables) without applying a one-way salted cryptographic password hash.',
    potentialImpact:
      'A database leak, backup exposure, or log read immediately reveals every user’s plaintext password, enabling account takeover and credential-stuffing attacks.',
    recommendedApproach:
      'Hash every password with a slow, salted password-hashing function (bcrypt, argon2, or hashlib.scrypt) before persistence and verify using constant-time hash comparison.',
  },
  'Broken Authorization': {
    whyVulnerable:
      'An access control or authorization condition contains a logic flaw (such as `or True` or missing ownership verification) that allows checks to pass unconditionally.',
    potentialImpact:
      'Unauthenticated or low-privilege users can bypass authorization boundaries and perform privileged actions or access other users’ private data.',
    recommendedApproach:
      'Remove unconditional bypass clauses (`or True`), deny access by default, and enforce explicit server-side role and resource-ownership checks on every protected operation.',
  },
  'Broken Authentication': {
    whyVulnerable:
      'Authentication verification logic has weaknesses that allow attackers to bypass identity checks or forge credentials.',
    potentialImpact:
      'Attackers can impersonate legitimate users or administrative accounts without valid credentials.',
    recommendedApproach:
      'Use standard, well-tested authentication workflows with verified session tokens, constant-time comparisons, and strict failure paths.',
  },
  'Insecure Deserialization': {
    whyVulnerable:
      'Deserializers like Python pickle or unsafe yaml.load can reconstruct arbitrary object graphs and invoke class constructors during parsing.',
    potentialImpact:
      'Deserializing attacker-controlled payloads can trigger remote code execution or denial of service.',
    recommendedApproach:
      'Use data-only formats like JSON or yaml.safe_load(), and validate deserialized fields against an explicit schema.',
  },
  'Insecure Transport': {
    whyVulnerable:
      'TLS certificate validation is disabled (e.g., verify=False or rejectUnauthorized: false), accepting untrusted or forged server certificates.',
    potentialImpact:
      'Network attackers can intercept, read, or tamper with encrypted traffic via Man-in-the-Middle attacks.',
    recommendedApproach:
      'Keep TLS certificate verification enabled and configure trusted CA certificates rather than disabling validation.',
  },
  'Path Traversal': {
    whyVulnerable:
      'A file system path appears constructed from external input without verifying that the resolved path stays inside the intended base directory.',
    potentialImpact:
      'Sequences like `../` can allow attackers to read sensitive files (configuration, keys) or overwrite application files outside the workspace.',
    recommendedApproach:
      'Normalize and resolve paths (Path.resolve() / path.resolve()), reject `..` segments, and assert the resolved path starts with the canonical base directory.',
  },
  'Cross-Site Scripting': {
    whyVulnerable:
      'Untrusted data is inserted into an HTML or DOM sink (such as innerHTML, document.write, or dangerouslySetInnerHTML) without contextual encoding or sanitization.',
    potentialImpact:
      'Attackers can execute arbitrary JavaScript in victims’ browsers to steal session cookies, perform unauthorized actions, or deface the UI.',
    recommendedApproach:
      'Render plain text with safe DOM APIs (textContent or standard JSX interpolation) and sanitize any required rich HTML with a strict library like DOMPurify.',
  },
  'Open Redirect': {
    whyVulnerable:
      'A redirect destination is taken from user-controlled input without validating the target host or path.',
    potentialImpact:
      'Attackers can craft trusted links that redirect users to phishing or malware domains.',
    recommendedApproach:
      'Validate redirect targets against an allowlist of relative application paths or trusted domains.',
  },
  'Vulnerable Dependency': {
    whyVulnerable:
      'A third-party package declared in your dependency manifest matches a known public vulnerability advisory.',
    potentialImpact:
      'Depending on how your project uses the library, attackers may exploit known flaws in the dependency.',
    recommendedApproach:
      'Upgrade the affected package to a patched version listed in the advisory and re-run OSV-Scanner to verify.',
  },
  'Error Handling': {
    whyVulnerable:
      'Broad exception handlers that silently ignore errors (`except: pass`) conceal unexpected failures and security checks.',
    potentialImpact:
      'Authentication, validation, or file-handling errors can fail open silently without alerting developers or operators.',
    recommendedApproach:
      'Catch specific exception classes, log diagnostic context safely without secrets, and fail closed on security-critical paths.',
  },
};

export function buildFindingGuidance(params: {
  category: string;
  cweId?: string | null;
  recommendation?: string | null;
}): FindingGuidance {
  const base = GUIDANCE_BY_CATEGORY[params.category] || {
    whyVulnerable:
      'Static analysis identified a coding or configuration pattern that weakens security boundaries or violates secure coding practices.',
    potentialImpact:
      'Depending on reachability and deployment exposure, attackers could abuse this weakness to compromise data confidentiality, integrity, or service availability.',
    recommendedApproach:
      'Review the flagged construct against OWASP and CWE best practices and replace unsafe patterns with validated, defensive implementations.',
  };

  return {
    whyVulnerable: base.whyVulnerable,
    potentialImpact: base.potentialImpact,
    recommendedApproach:
      params.recommendation && params.recommendation.trim().length > 15
        ? params.recommendation.trim()
        : base.recommendedApproach,
  };
}

export function getFindingSourceContext(params: {
  findingId: string;
  userId: string;
  contextRadius?: number;
}): SourceContext {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT id, scan_id, project_id, file_path, start_line, end_line, start_col, end_col, language
       FROM findings
       WHERE id = ? AND user_id = ?`
    )
    .get(params.findingId, params.userId) as Record<string, unknown> | undefined;

  if (!row) {
    return {
      available: false,
      fromSnapshot: false,
      snapshotNotice: 'Finding not found or access denied.',
      filePath: '',
      language: 'Source',
      startLine: 1,
      endLine: 1,
      startCol: null,
      endCol: null,
      contextStartLine: 1,
      contextEndLine: 1,
      totalLines: 0,
      lines: [],
    };
  }

  let safeFilePath = String(row.file_path || '');
  try {
    safeFilePath = sanitizeRelativePath(safeFilePath);
  } catch {
    return {
      available: false,
      fromSnapshot: false,
      snapshotNotice: 'Invalid file path recorded for finding.',
      filePath: safeFilePath,
      language: String(row.language || 'Source'),
      startLine: Number(row.start_line || 1),
      endLine: Number(row.end_line || 1),
      startCol: row.start_col != null ? Number(row.start_col) : null,
      endCol: row.end_col != null ? Number(row.end_col) : null,
      contextStartLine: 1,
      contextEndLine: 1,
      totalLines: 0,
      lines: [],
    };
  }

  const scanId = String(row.scan_id);
  const startLine = Math.max(1, Number(row.start_line || 1));
  const endLine = Math.max(startLine, Number(row.end_line || startLine));
  const startCol = row.start_col != null ? Number(row.start_col) : null;
  const endCol = row.end_col != null ? Number(row.end_col) : null;
  const language = String(row.language || 'Source');

  // Strictly prefer the historical scan snapshot corresponding to this scan.
  // Never silently substitute the current mutable project file for older scans without a snapshot.
  const snapshot = db
    .prepare(
      `SELECT content, language
       FROM scan_file_snapshots
       WHERE scan_id = ? AND file_path = ? AND user_id = ?`
    )
    .get(scanId, safeFilePath, params.userId) as { content: string; language: string } | undefined;

  if (!snapshot) {
    return {
      available: false,
      fromSnapshot: false,
      snapshotNotice:
        'Original scanned source snapshot is unavailable for this historical scan. Run a new scan to capture an immutable source snapshot.',
      filePath: safeFilePath,
      language,
      startLine,
      endLine,
      startCol,
      endCol,
      contextStartLine: startLine,
      contextEndLine: endLine,
      totalLines: 0,
      lines: [],
    };
  }

  const allLines = snapshot.content.split(/\r?\n/);
  const totalLines = allLines.length;
  const radius = Math.max(5, Math.min(10, params.contextRadius ?? 7));
  const ctxStart = Math.max(1, startLine - radius);
  const ctxEnd = Math.min(totalLines, endLine + radius);

  const lines: SourceContextLine[] = [];
  for (let ln = ctxStart; ln <= ctxEnd; ln++) {
    const rawLine = allLines[ln - 1] ?? '';
    const isTarget = ln >= startLine && ln <= endLine;

    let lineStartCol: number | null = null;
    let lineEndCol: number | null = null;

    if (isTarget && startCol !== null && endCol !== null) {
      if (startLine === endLine) {
        lineStartCol = startCol;
        lineEndCol = endCol;
      } else if (ln === startLine) {
        lineStartCol = startCol;
        lineEndCol = rawLine.length + 1;
      } else if (ln === endLine) {
        lineStartCol = 1;
        lineEndCol = endCol;
      }
    }

    const safeLine = redactLineWithColumns(rawLine, lineStartCol, lineEndCol);
    lines.push({
      lineNumber: ln,
      text: safeLine.text,
      isTarget,
      highlightStartCol: safeLine.highlightStartCol,
      highlightEndCol: safeLine.highlightEndCol,
    });
  }

  return {
    available: true,
    fromSnapshot: true,
    snapshotNotice: null,
    filePath: safeFilePath,
    language: snapshot.language || language,
    startLine,
    endLine,
    startCol,
    endCol,
    contextStartLine: ctxStart,
    contextEndLine: ctxEnd,
    totalLines,
    lines,
  };
}

export function getFindingFullSnapshot(params: {
  findingId: string;
  userId: string;
}): {
  available: boolean;
  fromSnapshot: boolean;
  notice: string | null;
  filePath: string;
  language: string;
  startLine: number;
  endLine: number;
  content: string | null;
} {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT scan_id, file_path, start_line, end_line, language
       FROM findings
       WHERE id = ? AND user_id = ?`
    )
    .get(params.findingId, params.userId) as Record<string, unknown> | undefined;

  if (!row) {
    return {
      available: false,
      fromSnapshot: false,
      notice: 'Finding not found or access denied.',
      filePath: '',
      language: 'Source',
      startLine: 1,
      endLine: 1,
      content: null,
    };
  }

  const safeFilePath = sanitizeRelativePath(String(row.file_path || ''));
  const snapshot = db
    .prepare(
      `SELECT content, language
       FROM scan_file_snapshots
       WHERE scan_id = ? AND file_path = ? AND user_id = ?`
    )
    .get(String(row.scan_id), safeFilePath, params.userId) as
    | { content: string; language: string }
    | undefined;

  if (!snapshot) {
    return {
      available: false,
      fromSnapshot: false,
      notice:
        'Original scanned source snapshot is unavailable for this historical scan. Run a new scan to view the full scanned file.',
      filePath: safeFilePath,
      language: String(row.language || 'Source'),
      startLine: Number(row.start_line || 1),
      endLine: Number(row.end_line || 1),
      content: null,
    };
  }

  return {
    available: true,
    fromSnapshot: true,
    notice: null,
    filePath: safeFilePath,
    language: snapshot.language || String(row.language || 'Source'),
    startLine: Number(row.start_line || 1),
    endLine: Number(row.end_line || 1),
    content: redactTextSecrets(snapshot.content),
  };
}
