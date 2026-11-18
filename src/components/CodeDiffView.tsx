import { useMemo } from 'react';

interface DiffLine {
  type: 'context' | 'removed' | 'added';
  oldNum: number | null;
  newNum: number | null;
  text: string;
}

function computeLineDiff(original: string, proposed: string): DiffLine[] {
  const a = original.split(/\r?\n/);
  const b = proposed.split(/\r?\n/);

  // Simple LCS-based line diff (bounded for performance on typical source files)
  const m = a.length;
  const n = b.length;

  if (m * n > 250000) {
    // Fallback side-by-side line summary for huge files
    const out: DiffLine[] = [];
    const maxLen = Math.max(m, n);
    for (let i = 0; i < maxLen; i++) {
      if (i < m && i < n && a[i] === b[i]) {
        out.push({ type: 'context', oldNum: i + 1, newNum: i + 1, text: a[i] });
      } else {
        if (i < m) out.push({ type: 'removed', oldNum: i + 1, newNum: null, text: a[i] });
        if (i < n) out.push({ type: 'added', oldNum: null, newNum: i + 1, text: b[i] });
      }
    }
    return out;
  }

  const dp: Uint16Array[] = Array.from({ length: m + 1 }, () => new Uint16Array(n + 1));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (a[i] === b[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const lines: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      lines.push({ type: 'context', oldNum: i + 1, newNum: j + 1, text: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      lines.push({ type: 'removed', oldNum: i + 1, newNum: null, text: a[i] });
      i++;
    } else {
      lines.push({ type: 'added', oldNum: null, newNum: j + 1, text: b[j] });
      j++;
    }
  }
  while (i < m) {
    lines.push({ type: 'removed', oldNum: i + 1, newNum: null, text: a[i] });
    i++;
  }
  while (j < n) {
    lines.push({ type: 'added', oldNum: null, newNum: j + 1, text: b[j] });
    j++;
  }

  return lines;
}

export function CodeDiffView({
  originalCode,
  proposedCode,
  filePath,
}: {
  originalCode: string;
  proposedCode: string;
  filePath: string;
}) {
  const diffLines = useMemo(() => computeLineDiff(originalCode, proposedCode), [originalCode, proposedCode]);

  const stats = useMemo(() => {
    let added = 0;
    let removed = 0;
    for (const l of diffLines) {
      if (l.type === 'added') added++;
      if (l.type === 'removed') removed++;
    }
    return { added, removed };
  }, [diffLines]);

  return (
    <div className="rounded-lg border border-slate-800 bg-[#060a14] overflow-hidden">
      <div className="flex items-center justify-between gap-4 border-b border-slate-800 bg-[#0b1222] px-4 py-2 text-xs">
        <span className="font-mono text-slate-300 truncate">{filePath}</span>
        <div className="flex items-center gap-3 font-mono tabular-nums shrink-0">
          <span className="text-emerald-400">+{stats.added} added</span>
          <span className="text-rose-400">-{stats.removed} removed</span>
        </div>
      </div>
      <div className="max-h-96 overflow-auto font-mono text-xs leading-5">
        {diffLines.map((line, idx) => {
          const rowClass =
            line.type === 'added'
              ? 'bg-emerald-950/35 text-emerald-200'
              : line.type === 'removed'
                ? 'bg-rose-950/35 text-rose-200'
                : 'text-slate-300';
          const marker = line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' ';
          return (
            <div key={idx} className={`flex px-2 py-0.5 ${rowClass}`}>
              <span className="w-9 shrink-0 select-none text-right pr-2 text-slate-600 tabular-nums">
                {line.oldNum ?? ''}
              </span>
              <span className="w-9 shrink-0 select-none text-right pr-2 text-slate-600 tabular-nums">
                {line.newNum ?? ''}
              </span>
              <span className="w-4 shrink-0 select-none opacity-75">{marker}</span>
              <pre className="whitespace-pre-wrap break-all flex-1">{line.text || ' '}</pre>
            </div>
          );
        })}
      </div>
    </div>
  );
}
