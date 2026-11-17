import { useState } from 'react';
import {
  Check,
  Download,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from 'lucide-react';
import {
  buildSocForensicExportBundle,
  formatSocForensicExportJson,
  type ChainVerificationReport,
  type LedgerEntry,
} from '../lib/forensicsLedger';
import { StatusIndicator } from './StatusIndicator';

interface ForensicsLedgerViewProps {
  entries: LedgerEntry[];
  chainReport: ChainVerificationReport | null;
  hasTamper: boolean;
  onVerifyChain: () => Promise<void>;
  onTamperStep: (stepIndex: number) => Promise<void>;
  onRestoreLedger: () => Promise<void>;
}

export function ForensicsLedgerView({
  entries,
  chainReport,
  hasTamper,
  onVerifyChain,
  onTamperStep,
  onRestoreLedger,
}: ForensicsLedgerViewProps) {
  const [exportState, setExportState] = useState<'idle' | 'exporting' | 'done'>('idle');

  const handleExportJson = async () => {
    setExportState('exporting');
    try {
      const bundle = await buildSocForensicExportBundle({
        ledgerEntries: entries,
        chainReport,
      });
      const formattedJson = formatSocForensicExportJson(bundle);
      const blob = new Blob([formattedJson], {
        type: 'application/json;charset=utf-8',
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const stamp = bundle.exportedAtIso.replace(/[:.]/g, '-');
      link.href = url;
      link.download = `soc-forensics-ledger-${stamp}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      setExportState('done');
      setTimeout(() => setExportState('idle'), 2000);
    } catch {
      setExportState('idle');
    }
  };

  const isChainValid = chainReport ? chainReport.valid : true;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-500">
            <span>Google DeepMind (#143922037276975814)</span>
            <span aria-hidden="true">·</span>
            <span>Snowflake (#ASHREQ-8175)</span>
            <span aria-hidden="true">·</span>
            <span>Structured Trajectory Replay & Forensics</span>
          </div>
          <h1 className="text-xl font-bold text-slate-900">
            TrajectoryForensicsLedger — Chained SHA-256 Forensics Ledger
          </h1>
        </div>
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {hasTamper && (
            <button
              type="button"
              onClick={() => onRestoreLedger()}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Restore Trusted Ledger</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => onVerifyChain()}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Verify Full Hash Chain</span>
          </button>
          <button
            type="button"
            onClick={() => void handleExportJson()}
            disabled={exportState === 'exporting'}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {exportState === 'done' ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
                <span>Exported SOC JSON</span>
              </>
            ) : (
              <>
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Export SOC Forensics JSON</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Integrity Banner */}
      <div
        className={`rounded-lg border p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 ${
          isChainValid
            ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
            : 'bg-rose-50/70 border-rose-200 text-rose-950'
        }`}
      >
        <div className="flex items-start gap-2.5">
          {isChainValid ? (
            <ShieldCheck className="h-5 w-5 text-emerald-700 shrink-0 mt-0.5" aria-hidden="true" />
          ) : (
            <ShieldAlert className="h-5 w-5 text-rose-700 shrink-0 mt-0.5" aria-hidden="true" />
          )}
          <div>
            <div className="text-sm font-semibold">
              {isChainValid
                ? `SHA-256 Hash Chain Verified (${entries.length} forensic entries)`
                : `Ledger Tampering Detected! Broken at Step #${chainReport?.brokenAtIndex}`}
            </div>
            <div className="text-xs mt-0.5">
              {isChainValid
                ? 'Every hypothesis, tool call payload, and verdict from GENESIS_HASH (0x0000...0000) to Tip Hash is continuously verifiable.'
                : chainReport?.failureReason}
            </div>
          </div>
        </div>
        <div className="text-xs font-mono tabular-nums text-slate-700 shrink-0">
          Tip: {entries.length > 0 ? `${entries[entries.length - 1].entryHash.slice(0, 16)}…` : 'GENESIS'}
        </div>
      </div>

      {/* Ledger Timeline */}
      <div className="space-y-3">
        {entries.map((entry) => {
          const stepResult = chainReport?.stepResults.find(
            (r) => r.stepIndex === entry.stepIndex
          );
          const brokenHere = stepResult ? !stepResult.valid : false;

          return (
            <div
              key={`${entry.stepIndex}-${entry.entryHash}`}
              className={`bg-white border rounded-lg p-4 space-y-3 ${
                brokenHere ? 'border-rose-400 bg-rose-50/30' : 'border-slate-200'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 border-b border-slate-100 pb-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="text-sm font-mono font-bold tabular-nums text-slate-900">
                    Step #{entry.stepIndex}
                  </span>
                  <span className="text-xs font-mono text-slate-500">
                    {entry.phase} · {entry.toolName}
                  </span>
                  <StatusIndicator
                    compact
                    tone={
                      brokenHere
                        ? 'danger'
                        : entry.verdict.includes('QUARANTINED') ||
                          entry.verdict.includes('ESCALATED') ||
                          entry.verdict.includes('BLOCK')
                        ? 'warning'
                        : 'success'
                    }
                    label={brokenHere ? `Hash Mismatch (${entry.verdict})` : entry.verdict}
                  />
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[11px] font-mono tabular-nums text-slate-500">
                    {entry.timestampIso}
                  </span>
                  <button
                    type="button"
                    onClick={() => onTamperStep(entry.stepIndex)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-rose-700 bg-rose-50 border border-rose-200 rounded hover:bg-rose-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Wrench className="h-3 w-3" aria-hidden="true" />
                    <span>Simulate Tamper on Step {entry.stepIndex}</span>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1.5">
                  <div className="text-slate-500 font-medium">Hypothesis & Execution Summary</div>
                  <div className="text-slate-900 font-medium">{entry.hypothesis}</div>
                  <div className="text-slate-600">{entry.resultSummary}</div>
                  <div className="text-[11px] font-mono text-slate-500 pt-1">
                    Compliance Ref: {entry.complianceRef}
                  </div>
                </div>
                <div className="space-y-1.5 font-mono text-[11px] tabular-nums bg-slate-50 border border-slate-200/80 rounded p-3 break-all">
                  <div className="text-slate-600">
                    <span className="text-slate-400">toolArgs: </span>
                    {JSON.stringify(entry.toolArgs)}
                  </div>
                  <div className="text-slate-600">
                    <span className="text-slate-400">prevHash: </span>
                    {entry.prevHash}
                  </div>
                  <div className={brokenHere ? 'text-rose-700 font-semibold' : 'text-slate-900'}>
                    <span className="text-slate-400">entryHash: </span>
                    {entry.entryHash}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
