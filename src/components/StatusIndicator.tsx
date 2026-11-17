import { AlertTriangle, CheckCircle2, Lock, ShieldAlert } from 'lucide-react';

export type IndicatorTone = 'success' | 'warning' | 'danger' | 'neutral';

interface StatusIndicatorProps {
  tone: IndicatorTone;
  label: string;
  compact?: boolean;
}

const TONE_STYLES: Record<IndicatorTone, string> = {
  success: 'bg-emerald-50 text-emerald-800 border-emerald-200',
  warning: 'bg-amber-50 text-amber-800 border-amber-200',
  danger: 'bg-rose-50 text-rose-800 border-rose-200',
  neutral: 'bg-slate-100 text-slate-700 border-slate-200',
};

export function StatusIndicator({ tone, label, compact = false }: StatusIndicatorProps) {
  const Icon =
    tone === 'success'
      ? CheckCircle2
      : tone === 'danger'
      ? ShieldAlert
      : tone === 'warning'
      ? AlertTriangle
      : Lock;

  return (
    <span
      className={`inline-flex items-center gap-1.5 max-w-full rounded border font-medium whitespace-nowrap shrink-0 ${
        compact ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-0.5 text-[11px] sm:text-xs'
      } ${TONE_STYLES[tone]}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span className="truncate">{label}</span>
    </span>
  );
}
