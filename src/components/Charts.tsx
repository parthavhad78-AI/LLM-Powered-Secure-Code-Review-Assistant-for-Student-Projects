import type { DashboardStats } from '../../shared/types';

export function SeverityDistributionChart({ stats }: { stats: DashboardStats }) {
  const items = [
    { label: 'Critical', value: stats.criticalFindings, color: '#f43f5e' },
    { label: 'High', value: stats.highFindings, color: '#fb923c' },
    { label: 'Medium', value: stats.mediumFindings, color: '#fbbf24' },
    { label: 'Low', value: stats.lowFindings, color: '#38bdf8' },
    { label: 'Informational', value: stats.infoFindings, color: '#94a3b8' },
  ];
  const total = items.reduce((acc, i) => acc + i.value, 0);

  return (
    <div className="space-y-4">
      <div className="h-3.5 w-full overflow-hidden rounded bg-slate-800/90 flex">
        {total === 0 ? (
          <div className="h-full w-full bg-slate-800" />
        ) : (
          items.map((item) => {
            if (item.value === 0) return null;
            const pct = (item.value / total) * 100;
            return (
              <div
                key={item.label}
                style={{ width: `${pct}%`, backgroundColor: item.color }}
                title={`${item.label}: ${item.value}`}
                className="h-full transition-all duration-300"
              />
            );
          })
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {items.map((item) => (
          <div key={item.label} className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="h-2.5 w-2.5 rounded-sm shrink-0" style={{ backgroundColor: item.color }} />
              <span>{item.label}</span>
            </div>
            <p className="font-mono text-lg font-semibold text-slate-100 tabular-nums">{item.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CategoryBarChart({
  data,
}: {
  data: Array<{ category: string; count: number }>;
}) {
  if (data.length === 0) {
    return (
      <div className="py-10 text-center text-sm text-slate-500">
        No vulnerability categories recorded yet. Run a scan to populate distribution data.
      </div>
    );
  }

  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="space-y-3">
      {data.map((item) => {
        const widthPct = Math.max(6, Math.round((item.count / max) * 100));
        return (
          <div key={item.category} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 truncate pr-3">{item.category}</span>
              <span className="font-mono text-slate-400 tabular-nums shrink-0">{item.count}</span>
            </div>
            <div className="h-2 w-full rounded bg-slate-800/80 overflow-hidden">
              <div
                className="h-full rounded bg-cyan-500/85"
                style={{ width: `${widthPct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function ScanActivityChart({
  data,
}: {
  data: Array<{ date: string; scans: number; findings: number }>;
}) {
  if (data.length === 0) {
    return (
      <div className="py-10 text-center text-sm text-slate-500">
        No scan activity recorded yet.
      </div>
    );
  }

  const width = 520;
  const height = 160;
  const padX = 28;
  const padY = 20;
  const maxVal = Math.max(...data.map((d) => Math.max(d.scans, d.findings)), 1);

  const barWidth = Math.max(12, Math.min(34, (width - padX * 2) / data.length - 8));

  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-40">
        {/* Baseline */}
        <line
          x1={padX}
          y1={height - padY}
          x2={width - padX}
          y2={height - padY}
          stroke="#1e293b"
          strokeWidth="1"
        />
        {data.map((pt, idx) => {
          const step = (width - padX * 2) / data.length;
          const x = padX + idx * step + (step - barWidth) / 2;
          const findingsH = Math.max(2, ((pt.findings || 0) / maxVal) * (height - padY * 2));
          const scansH = Math.max(3, (pt.scans / maxVal) * (height - padY * 2));
          return (
            <g key={pt.date}>
              <rect
                x={x}
                y={height - padY - findingsH}
                width={barWidth * 0.55}
                height={findingsH}
                rx="2"
                fill="#3b82f6"
                opacity="0.85"
              >
                <title>{`${pt.date}: ${pt.findings} findings`}</title>
              </rect>
              <rect
                x={x + barWidth * 0.6}
                y={height - padY - scansH}
                width={barWidth * 0.4}
                height={scansH}
                rx="2"
                fill="#06b6d4"
              >
                <title>{`${pt.date}: ${pt.scans} scan(s)`}</title>
              </rect>
              <text
                x={x + barWidth / 2}
                y={height - 5}
                textAnchor="middle"
                fill="#64748b"
                fontSize="9"
                fontFamily="JetBrains Mono, monospace"
              >
                {pt.date.slice(5)}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex items-center gap-5 text-xs text-slate-400">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm bg-blue-500" />
          Findings Detected
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm bg-cyan-500" />
          Scans Executed
        </span>
      </div>
    </div>
  );
}

export function RemediationProgressMeter({
  total,
  remediated,
}: {
  total: number;
  remediated: number;
}) {
  const pct = total > 0 ? Math.round((remediated / total) * 100) : 0;
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (pct / 100) * circumference;

  return (
    <div className="flex items-center gap-6">
      <div className="relative h-28 w-28 shrink-0">
        <svg viewBox="0 0 108 108" className="h-full w-full -rotate-90">
          <circle
            cx="54"
            cy="54"
            r={radius}
            fill="none"
            stroke="#1e293b"
            strokeWidth="9"
          />
          <circle
            cx="54"
            cy="54"
            r={radius}
            fill="none"
            stroke="#10b981"
            strokeWidth="9"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-xl font-semibold text-slate-100 tabular-nums">{pct}%</span>
        </div>
      </div>
      <div className="space-y-1.5 text-sm">
        <p className="font-medium text-slate-200">Remediation Progress</p>
        <p className="text-xs text-slate-400">
          <span className="font-mono text-emerald-400 tabular-nums">{remediated}</span> of{' '}
          <span className="font-mono text-slate-200 tabular-nums">{total}</span> findings validated as fixed.
        </p>
      </div>
    </div>
  );
}
