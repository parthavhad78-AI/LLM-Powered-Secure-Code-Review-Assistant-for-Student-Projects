import { AlertCircle, AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react';
import type { DetectionSource, RemediationStatus, Severity, ValidationStatus } from '../../shared/types';

export function SeverityIndicator({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    Critical: 'text-rose-300 bg-rose-950/60 border-rose-800/70',
    High: 'text-orange-300 bg-orange-950/60 border-orange-800/70',
    Medium: 'text-amber-300 bg-amber-950/60 border-amber-800/70',
    Low: 'text-sky-300 bg-sky-950/60 border-sky-800/70',
    Informational: 'text-slate-300 bg-slate-800/70 border-slate-700',
  };

  const Icon =
    severity === 'Critical'
      ? ShieldAlert
      : severity === 'High'
        ? AlertTriangle
        : severity === 'Medium'
          ? AlertCircle
          : Info;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${styles[severity]}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span>{severity}</span>
    </span>
  );
}

export function DetectionSourceLabel({ source }: { source: DetectionSource }) {
  const map: Record<DetectionSource, { label: string; cls: string }> = {
    confirmed_tool: { label: 'Confirmed Tool', cls: 'text-cyan-300' },
    pattern_based: { label: 'Pattern-Based', cls: 'text-amber-300' },
    dependency_advisory: { label: 'Dependency Advisory', cls: 'text-violet-300' },
  };
  const info = map[source] || { label: source, cls: 'text-slate-300' };
  return <span className={`text-xs font-medium ${info.cls}`}>{info.label}</span>;
}

export function RemediationStatusLabel({ status }: { status: RemediationStatus }) {
  const map: Record<RemediationStatus, { label: string; cls: string }> = {
    open: { label: 'Open', cls: 'text-rose-300' },
    in_review: { label: 'In Review', cls: 'text-amber-300' },
    approved: { label: 'Applied (Unvalidated)', cls: 'text-sky-300' },
    remediated: { label: 'Remediated', cls: 'text-emerald-300' },
    accepted_risk: { label: 'Accepted Risk', cls: 'text-slate-400' },
    false_positive: { label: 'Marked False Positive', cls: 'text-slate-400' },
  };
  const info = map[status] || { label: status, cls: 'text-slate-300' };
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium whitespace-nowrap ${info.cls}`}>
      {status === 'remediated' && <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />}
      <span>{info.label}</span>
    </span>
  );
}

export function ValidationStatusLabel({ status }: { status: ValidationStatus }) {
  const map: Record<ValidationStatus, { label: string; cls: string }> = {
    pending: { label: 'Pending Validation', cls: 'text-slate-400 border-slate-700 bg-slate-900' },
    validated: { label: 'Validated Fixed', cls: 'text-emerald-300 border-emerald-800/70 bg-emerald-950/50' },
    partially_validated: { label: 'Partially Validated', cls: 'text-amber-300 border-amber-800/70 bg-amber-950/50' },
    not_resolved: { label: 'Not Resolved', cls: 'text-rose-300 border-rose-800/70 bg-rose-950/50' },
    new_issues_detected: { label: 'New Issues Detected', cls: 'text-orange-300 border-orange-800/70 bg-orange-950/50' },
    validation_unavailable: { label: 'Validation Unavailable', cls: 'text-slate-300 border-slate-700 bg-slate-800/70' },
  };
  const info = map[status] || map.pending;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${info.cls}`}>
      <span>{info.label}</span>
    </span>
  );
}
