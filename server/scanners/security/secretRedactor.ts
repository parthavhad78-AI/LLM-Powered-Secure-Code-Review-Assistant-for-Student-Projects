export function redactSecretValue(secret: string): string {
  if (!secret) return '****';
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return '*'.repeat(Math.max(4, trimmed.length));
  }
  const prefix = trimmed.slice(0, 4);
  const suffix = trimmed.slice(-4);
  const maskedLen = Math.min(16, Math.max(4, trimmed.length - 8));
  return `${prefix}${'*'.repeat(maskedLen)}${suffix}`;
}

const SECRET_PATTERNS: Array<{ pattern: RegExp; replacer: (match: string, ...groups: string[]) => string }> = [
  {
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacer: () => '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----',
  },
  {
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    replacer: (_m, key) => redactSecretValue(key),
  },
  {
    pattern: /\b(gh[pousr]_[A-Za-z0-9_]{16,})\b/g,
    replacer: (_m, token) => redactSecretValue(token),
  },
  {
    pattern: /\b(AIza[0-9A-Za-z_-]{20,})\b/g,
    replacer: (_m, key) => redactSecretValue(key),
  },
  {
    pattern: /\b(sk_(?:live|test)_[A-Za-z0-9]{12,}|sk-[A-Za-z0-9_-]{16,})\b/g,
    replacer: (_m, key) => redactSecretValue(key),
  },
  {
    pattern: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g,
    replacer: (_m, jwt) => redactSecretValue(jwt),
  },
  {
    pattern: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/]+:)([^@\s]+)(@[^\s'"]+)/gi,
    replacer: (_m, prefix, pass, suffix) => `${prefix}${redactSecretValue(pass)}${suffix}`,
  },
  {
    // Match credential/secret assignments without stripping ordinary identifiers or SQL SELECT clauses
    pattern: /(\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|jwt[_-]?secret|signing[_-]?key|private[_-]?key|db[_-]?pass(?:word)?|admin[_-]?password|hardcoded[_-]?(?:password|secret|key|token)|password|passwd|pwd)\s*[:=]\s*['"])([^'"\r\n]{4,})(['"])/gi,
    replacer: (full, prefix, val, quote) => {
      // Never corrupt already-redacted masks
      if (/^\*+$/.test(val)) return full;
      return `${prefix}${redactSecretValue(val)}${quote}`;
    },
  },
];

export function redactTextSecrets(input: string): string {
  if (!input) return '';
  let output = input;
  for (const { pattern, replacer } of SECRET_PATTERNS) {
    output = output.replace(pattern, replacer);
  }
  return output;
}

const AUTH_PLACEHOLDER_PATTERNS = [
  /^requires\s+login\.?$/i,
  /^login\s+required\.?$/i,
  /^authentication\s+required\.?$/i,
  /^please\s+log\s*in\.?$/i,
  /^unauthorized\.?$/i,
];

/**
 * Detects external scanner or HTTP auth placeholder strings (e.g. Semgrep's
 * unauthenticated `extra.lines: "requires login"`) so they are never persisted
 * or rendered as source code or finding evidence.
 */
export function isAuthPlaceholderText(text: string | null | undefined): boolean {
  if (!text) return false;
  const trimmed = text.trim();
  return AUTH_PLACEHOLDER_PATTERNS.some((re) => re.test(trimmed));
}

export function sanitizeScannerSnippet(text: string | null | undefined): string {
  if (!text || isAuthPlaceholderText(text)) return '';
  return redactTextSecrets(text);
}

/**
 * Redacts secrets on a single source line while adjusting 1-based inclusive/exclusive
 * column highlight bounds if redaction shifted character positions.
 */
export function redactLineWithColumns(
  line: string,
  startCol: number | null,
  endCol: number | null
): { text: string; highlightStartCol: number | null; highlightEndCol: number | null } {
  const redacted = redactTextSecrets(line);
  if (startCol === null || endCol === null) {
    return { text: redacted, highlightStartCol: startCol, highlightEndCol: endCol };
  }
  if (redacted === line) {
    const clampedStart = Math.max(1, Math.min(startCol, Math.max(1, redacted.length + 1)));
    const clampedEnd = Math.max(clampedStart, Math.min(endCol, redacted.length + 1));
    return {
      text: redacted,
      highlightStartCol: clampedStart,
      highlightEndCol: clampedEnd,
    };
  }

  // If the line was redacted, scale/clamp columns proportionally so highlights never overflow
  const delta = redacted.length - line.length;
  const clampedStart = Math.max(1, Math.min(startCol, Math.max(1, redacted.length + 1)));
  const clampedEnd = Math.max(clampedStart, Math.min(endCol + delta, redacted.length + 1));
  return {
    text: redacted,
    highlightStartCol: clampedStart,
    highlightEndCol: clampedEnd,
  };
}
