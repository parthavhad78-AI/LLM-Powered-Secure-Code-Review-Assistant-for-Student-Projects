import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, FileCode2, Maximize2, X } from 'lucide-react';
import type { SourceContext } from '../../shared/types';
import { apiRequest } from '../api/client';

type TokenType =
  | 'plain'
  | 'keyword'
  | 'string'
  | 'comment'
  | 'number'
  | 'decorator'
  | 'builtin'
  | 'operator';

interface Token {
  type: TokenType;
  value: string;
}

const PYTHON_KEYWORDS = new Set([
  'False',
  'None',
  'True',
  'and',
  'as',
  'assert',
  'async',
  'await',
  'break',
  'class',
  'continue',
  'def',
  'del',
  'elif',
  'else',
  'except',
  'finally',
  'for',
  'from',
  'global',
  'if',
  'import',
  'in',
  'is',
  'lambda',
  'nonlocal',
  'not',
  'or',
  'pass',
  'raise',
  'return',
  'try',
  'while',
  'with',
  'yield',
]);

const JS_KEYWORDS = new Set([
  'as',
  'async',
  'await',
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'else',
  'enum',
  'export',
  'extends',
  'false',
  'finally',
  'for',
  'from',
  'function',
  'if',
  'implements',
  'import',
  'in',
  'instanceof',
  'interface',
  'let',
  'new',
  'null',
  'of',
  'package',
  'private',
  'protected',
  'public',
  'return',
  'static',
  'super',
  'switch',
  'this',
  'throw',
  'true',
  'try',
  'type',
  'typeof',
  'undefined',
  'var',
  'void',
  'while',
  'with',
  'yield',
]);

const BUILTINS = new Set([
  'print',
  'len',
  'range',
  'str',
  'int',
  'float',
  'dict',
  'list',
  'set',
  'open',
  'console',
  'JSON',
  'Math',
  'Object',
  'Array',
  'Promise',
  'Error',
  'process',
  'Buffer',
]);

function normalizeLangFamily(language: string, filePath: string): 'python' | 'js' | 'config' | 'other' {
  const lower = `${language} ${filePath}`.toLowerCase();
  if (lower.includes('python') || lower.endsWith('.py')) return 'python';
  if (
    lower.includes('javascript') ||
    lower.includes('typescript') ||
    /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(filePath)
  ) {
    return 'js';
  }
  if (
    lower.includes('json') ||
    lower.includes('yaml') ||
    lower.includes('yml') ||
    lower.includes('toml') ||
    lower.includes('env') ||
    /\.(json|ya?ml|toml|ini|cfg|env)$/i.test(filePath)
  ) {
    return 'config';
  }
  return 'other';
}

function tokenizeLine(line: string, family: 'python' | 'js' | 'config' | 'other'): Token[] {
  if (!line) return [{ type: 'plain', value: '' }];
  const tokens: Token[] = [];
  const keywords = family === 'python' ? PYTHON_KEYWORDS : family === 'js' ? JS_KEYWORDS : null;
  let i = 0;

  while (i < line.length) {
    const ch = line[i];

    // Comments
    if ((family === 'python' || family === 'config') && ch === '#') {
      tokens.push({ type: 'comment', value: line.slice(i) });
      break;
    }
    if (family === 'js' && ch === '/' && line[i + 1] === '/') {
      tokens.push({ type: 'comment', value: line.slice(i) });
      break;
    }

    // Strings (single, double, backtick)
    if (ch === '"' || ch === "'" || (family === 'js' && ch === '`')) {
      const quote = ch;
      let j = i + 1;
      while (j < line.length) {
        if (line[j] === '\\') {
          j += 2;
          continue;
        }
        if (line[j] === quote) {
          j++;
          break;
        }
        j++;
      }
      tokens.push({ type: 'string', value: line.slice(i, j) });
      i = j;
      continue;
    }

    // Decorators
    if (ch === '@' && (family === 'python' || family === 'js')) {
      let j = i + 1;
      while (j < line.length && /[A-Za-z0-9_.]/.test(line[j])) j++;
      tokens.push({ type: 'decorator', value: line.slice(i, j) });
      i = j;
      continue;
    }

    // Numbers
    if (/[0-9]/.test(ch) && (i === 0 || !/[A-Za-z0-9_]/.test(line[i - 1]))) {
      let j = i;
      while (j < line.length && /[0-9a-fA-FxXoObB._]/.test(line[j])) j++;
      tokens.push({ type: 'number', value: line.slice(i, j) });
      i = j;
      continue;
    }

    // Identifiers / Keywords / Config keys
    if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < line.length && /[A-Za-z0-9_-]/.test(line[j])) {
        if (family !== 'config' && line[j] === '-') break;
        j++;
      }
      const word = line.slice(i, j);
      if (keywords && keywords.has(word)) {
        tokens.push({ type: 'keyword', value: word });
      } else if (BUILTINS.has(word)) {
        tokens.push({ type: 'builtin', value: word });
      } else if (family === 'config' && /^\s*[:=]/.test(line.slice(j))) {
        tokens.push({ type: 'keyword', value: word });
      } else {
        tokens.push({ type: 'plain', value: word });
      }
      i = j;
      continue;
    }

    // Operators / punctuation
    if (/[=+\-*/%<>!&|^~?:]/.test(ch)) {
      let j = i + 1;
      while (j < line.length && /[=+\-*/%<>!&|^~?:]/.test(line[j])) j++;
      tokens.push({ type: 'operator', value: line.slice(i, j) });
      i = j;
      continue;
    }

    // Plain whitespace or delimiters
    let j = i + 1;
    while (j < line.length && !/['"`#@0-9A-Za-z_=+\-*/%<>!&|^~?:]/.test(line[j])) {
      j++;
    }
    tokens.push({ type: 'plain', value: line.slice(i, j) });
    i = j;
  }

  return tokens;
}

const TOKEN_CLASSES: Record<TokenType, string> = {
  plain: 'text-slate-200',
  keyword: 'text-cyan-300',
  string: 'text-emerald-300',
  comment: 'text-slate-500 italic',
  number: 'text-amber-300',
  decorator: 'text-violet-300',
  builtin: 'text-sky-300',
  operator: 'text-slate-400',
};

function renderHighlightedLine(
  text: string,
  family: 'python' | 'js' | 'config' | 'other',
  highlightStartCol: number | null,
  highlightEndCol: number | null
) {
  if (!text) {
    return <span>&nbsp;</span>;
  }

  const tokens = tokenizeLine(text, family);

  // Convert 1-based inclusive/exclusive highlight columns to 0-based indices
  const hasRange =
    highlightStartCol !== null &&
    highlightEndCol !== null &&
    highlightEndCol > highlightStartCol;
  const hlStart = hasRange ? Math.max(0, highlightStartCol! - 1) : -1;
  const hlEnd = hasRange ? Math.min(text.length, highlightEndCol! - 1) : -1;

  if (!hasRange || hlEnd <= hlStart) {
    return tokens.map((tok, idx) => (
      <span key={idx} className={TOKEN_CLASSES[tok.type]}>
        {tok.value}
      </span>
    ));
  }

  const nodes: React.ReactNode[] = [];
  let offset = 0;

  tokens.forEach((tok, idx) => {
    const tokStart = offset;
    const tokEnd = offset + tok.value.length;
    offset = tokEnd;

    if (tokEnd <= hlStart || tokStart >= hlEnd) {
      nodes.push(
        <span key={idx} className={TOKEN_CLASSES[tok.type]}>
          {tok.value}
        </span>
      );
      return;
    }

    const overlapStart = Math.max(tokStart, hlStart) - tokStart;
    const overlapEnd = Math.min(tokEnd, hlEnd) - tokStart;

    if (overlapStart > 0) {
      nodes.push(
        <span key={`${idx}-pre`} className={TOKEN_CLASSES[tok.type]}>
          {tok.value.slice(0, overlapStart)}
        </span>
      );
    }

    nodes.push(
      <mark
        key={`${idx}-hl`}
        className={`rounded-xs bg-rose-500/28 underline decoration-rose-400 decoration-wavy underline-offset-2 px-0.5 ${TOKEN_CLASSES[tok.type]}`}
      >
        {tok.value.slice(overlapStart, overlapEnd)}
      </mark>
    );

    if (overlapEnd < tok.value.length) {
      nodes.push(
        <span key={`${idx}-post`} className={TOKEN_CLASSES[tok.type]}>
          {tok.value.slice(overlapEnd)}
        </span>
      );
    }
  });

  return nodes;
}

interface FullSnapshotResponse {
  file: {
    available: boolean;
    fromSnapshot: boolean;
    notice: string | null;
    filePath: string;
    language: string;
    startLine: number;
    endLine: number;
    content: string | null;
  };
}

export function VulnerableCodeViewer({
  sourceContext,
  findingId,
  filePath,
}: {
  sourceContext: SourceContext | null | undefined;
  findingId: string;
  filePath: string;
}) {
  const [modalOpen, setModalOpen] = useState(false);
  const [fullLoading, setFullLoading] = useState(false);
  const [fullError, setFullError] = useState<string | null>(null);
  const [fullData, setFullData] = useState<FullSnapshotResponse['file'] | null>(null);
  const targetLineRef = useRef<HTMLDivElement | null>(null);

  const family = useMemo(
    () => normalizeLangFamily(sourceContext?.language || '', filePath),
    [sourceContext?.language, filePath]
  );

  useEffect(() => {
    setModalOpen(false);
    setFullData(null);
    setFullError(null);
  }, [findingId]);

  useEffect(() => {
    if (modalOpen && fullData?.available && targetLineRef.current) {
      targetLineRef.current.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }, [modalOpen, fullData]);

  async function handleOpenFullFile() {
    setModalOpen(true);
    if (fullData) return;
    setFullLoading(true);
    setFullError(null);
    try {
      const res = await apiRequest<FullSnapshotResponse>(
        `/api/findings/${encodeURIComponent(findingId)}/source?full=true`
      );
      setFullData(res.file);
    } catch (err) {
      setFullError(err instanceof Error ? err.message : 'Unable to retrieve scanned file snapshot.');
    } finally {
      setFullLoading(false);
    }
  }

  const fullLines = useMemo(() => {
    if (!fullData?.content) return [];
    return fullData.content.split(/\r?\n/);
  }, [fullData]);

  if (!sourceContext || !sourceContext.available || sourceContext.lines.length === 0) {
    return (
      <div className="rounded-lg border border-amber-800/60 bg-amber-950/25 p-4 flex items-start gap-3">
        <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-xs">
          <p className="font-semibold text-amber-200">Source Snapshot Unavailable</p>
          <p className="text-slate-300 leading-relaxed">
            {sourceContext?.snapshotNotice || 'Source evidence unavailable.'}
          </p>
        </div>
      </div>
    );
  }

  const locationRangeLabel =
    sourceContext.startLine === sourceContext.endLine
      ? `Line ${sourceContext.startLine}`
      : `Lines ${sourceContext.startLine}-${sourceContext.endLine}`;

  return (
    <>
      <div className="rounded-lg border border-slate-800 bg-[#060a14] overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 bg-[#0b1222] px-3.5 py-2 text-xs">
          <div className="flex items-center gap-2 min-w-0">
            <FileCode2 className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
            <span className="font-mono text-slate-200 truncate">{sourceContext.filePath}</span>
            <span className="text-slate-600">·</span>
            <span className="font-mono text-slate-400 tabular-nums shrink-0">
              {locationRangeLabel}
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-emerald-400/90 shrink-0">
              {sourceContext.fromSnapshot ? 'Scanned Snapshot' : 'Project File'}
            </span>
          </div>

          <button
            type="button"
            onClick={handleOpenFullFile}
            className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-[#0e1526] px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:border-cyan-500/50 hover:text-cyan-200 transition-colors shrink-0"
          >
            <Maximize2 className="h-3 w-3 text-cyan-400" />
            <span>View Full File</span>
          </button>
        </div>

        <div className="overflow-x-auto font-mono text-xs leading-5 py-1.5">
          {sourceContext.lines.map((line) => (
            <div
              key={line.lineNumber}
              className={`flex items-stretch px-3 py-0.5 ${
                line.isTarget
                  ? 'bg-rose-500/12 ring-1 ring-inset ring-rose-500/30'
                  : 'hover:bg-slate-800/25'
              }`}
            >
              <span
                className={`w-11 shrink-0 select-none text-right pr-3 tabular-nums ${
                  line.isTarget ? 'text-rose-300 font-semibold' : 'text-slate-600'
                }`}
              >
                {line.lineNumber}
              </span>
              <span className="w-4 shrink-0 select-none text-rose-400 font-semibold">
                {line.isTarget ? '>' : ' '}
              </span>
              <pre className="whitespace-pre flex-1">
                {renderHighlightedLine(
                  line.text,
                  family,
                  line.highlightStartCol,
                  line.highlightEndCol
                )}
              </pre>
            </div>
          ))}
        </div>
      </div>

      {/* Full Scanned File Modal */}
      {modalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`Full scanned file ${filePath}`}
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-xs"
        >
          <div className="flex max-h-[88vh] w-full max-w-5xl flex-col rounded-xl border border-slate-700 bg-[#0b1222] shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between gap-4 border-b border-slate-800 px-5 py-3.5">
              <div className="min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <FileCode2 className="h-4 w-4 text-cyan-400 shrink-0" />
                  <h3 className="font-mono text-sm font-semibold text-slate-100 truncate">
                    {filePath}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 font-mono tabular-nums">
                  {sourceContext.language} · Highlighting {locationRangeLabel} · Immutable Scan Snapshot
                </p>
              </div>
              <button
                type="button"
                aria-label="Close full file viewer"
                onClick={() => setModalOpen(false)}
                className="rounded-lg border border-slate-700 p-1.5 text-slate-400 hover:text-slate-100 hover:border-slate-600"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 overflow-auto bg-[#060a14] font-mono text-xs leading-5 py-2">
              {fullLoading ? (
                <div className="p-6 text-slate-400">Loading scanned source snapshot...</div>
              ) : fullError ? (
                <div className="p-6 text-rose-300">{fullError}</div>
              ) : !fullData?.available || !fullData.content ? (
                <div className="p-6 text-amber-200">
                  {fullData?.notice || 'Original scanned source snapshot is unavailable.'}
                </div>
              ) : (
                fullLines.map((lineText, idx) => {
                  const ln = idx + 1;
                  const isTarget = ln >= fullData.startLine && ln <= fullData.endLine;
                  const isFirstTarget = ln === fullData.startLine;
                  return (
                    <div
                      key={ln}
                      ref={isFirstTarget ? targetLineRef : undefined}
                      className={`flex items-stretch px-4 py-0.5 ${
                        isTarget
                          ? 'bg-rose-500/14 ring-1 ring-inset ring-rose-500/30'
                          : 'hover:bg-slate-800/25'
                      }`}
                    >
                      <span
                        className={`w-12 shrink-0 select-none text-right pr-3 tabular-nums ${
                          isTarget ? 'text-rose-300 font-semibold' : 'text-slate-600'
                        }`}
                      >
                        {ln}
                      </span>
                      <pre className="whitespace-pre flex-1">
                        {renderHighlightedLine(lineText, family, null, null)}
                      </pre>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
