import { useState } from 'react';
import { CheckCircle2, Plus, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';
import type {
  ITSMChangeRecord,
  ModelVerdict,
  SocVerificationResult,
} from '../lib/itsmVerifier';
import { SOC_SCENARIO_PRESETS } from '../lib/seedData';
import { StatusIndicator } from './StatusIndicator';

interface ItsmVerifierLabProps {
  itsmTable: ITSMChangeRecord[];
  lastResult: SocVerificationResult | null;
  onAddItsmRecord: (record: ITSMChangeRecord) => void;
  onVerifyVerdict: (params: {
    modelVerdict: ModelVerdict;
    claimedTicketId: string | null;
    observedHostname: string;
    eventTimestampIso: string;
    rawLog: string;
  }) => Promise<SocVerificationResult>;
}

export function ItsmVerifierLab({
  itsmTable,
  lastResult,
  onAddItsmRecord,
  onVerifyVerdict,
}: ItsmVerifierLabProps) {
  const initial = SOC_SCENARIO_PRESETS[0];
  const [selectedPresetId, setSelectedPresetId] = useState(initial.id);
  const [observedHostname, setObservedHostname] = useState(initial.observedHostname);
  const [eventTimestampIso, setEventTimestampIso] = useState(initial.eventTimestampIso);
  const [claimedTicketId, setClaimedTicketId] = useState(initial.claimedTicketId);
  const [modelVerdict, setModelVerdict] = useState<ModelVerdict>(initial.modelVerdict);
  const [rawLog, setRawLog] = useState(initial.rawLog);
  const [formError, setFormError] = useState<string | null>(null);

  const [showAddTicket, setShowAddTicket] = useState(false);
  const [newTicketId, setNewTicketId] = useState('CHG-2026-4200');
  const [newHostname, setNewHostname] = useState('prod-fin-core-01.internal');
  const [newStart, setNewStart] = useState('2026-11-17T01:00:00Z');
  const [newEnd, setNewEnd] = useState('2026-11-17T04:00:00Z');
  const [newSummary, setNewSummary] = useState('Emergency TLS rotation');

  const applyPreset = (id: string) => {
    const preset = SOC_SCENARIO_PRESETS.find((p) => p.id === id);
    if (!preset) return;
    setSelectedPresetId(preset.id);
    setObservedHostname(preset.observedHostname);
    setEventTimestampIso(preset.eventTimestampIso);
    setClaimedTicketId(preset.claimedTicketId);
    setModelVerdict(preset.modelVerdict);
    setRawLog(preset.rawLog);
    setFormError(null);
  };

  const handleRunVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!observedHostname.trim() || !eventTimestampIso.trim() || !rawLog.trim()) {
      setFormError('Observed hostname, event timestamp, and raw telemetry log are required.');
      return;
    }
    setFormError(null);
    await onVerifyVerdict({
      modelVerdict,
      claimedTicketId: claimedTicketId.trim() || null,
      observedHostname: observedHostname.trim(),
      eventTimestampIso: eventTimestampIso.trim(),
      rawLog,
    });
  };

  const handleCreateTicket = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTicketId.trim() || !newHostname.trim()) return;
    onAddItsmRecord({
      ticketId: newTicketId.trim().toUpperCase(),
      hostname: newHostname.trim(),
      approvedWindowStart: newStart.trim(),
      approvedWindowEnd: newEnd.trim(),
      changeOwner: 'soc-admin@corp.internal',
      summary: newSummary.trim() || 'Authorized maintenance window',
      status: 'APPROVED',
    });
    setShowAddTicket(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-500">
          <span>Defense Target: Poisoning the Watchtower</span>
          <span aria-hidden="true">·</span>
          <span>Envelope: &lt;untrusted_telemetry_{'{nonce}'}&gt;</span>
          <span aria-hidden="true">·</span>
          <span>Tuple Check: (ticket_id, hostname, approved_window)</span>
        </div>
        <h1 className="text-xl font-bold text-slate-900 mt-1">
          verify_soc_verdict_with_itsm — Dynamic Nonce & ITSM Cross-Verification Lab
        </h1>
      </div>

      {/* Scenario Presets */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-900">
          Select Adversarial AI SOC Triage Scenario
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {SOC_SCENARIO_PRESETS.map((preset) => {
            const active = selectedPresetId === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => applyPreset(preset.id)}
                className={`text-left p-3.5 rounded-md border transition-colors cursor-pointer ${
                  active
                    ? 'border-slate-900 bg-slate-50'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <div className="text-xs font-semibold text-slate-900">{preset.title}</div>
                <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                  {preset.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Two-Column Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <form
          onSubmit={handleRunVerify}
          className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-5 space-y-4"
        >
          <h2 className="text-sm font-semibold text-slate-900 border-b border-slate-100 pb-3">
            01. Telemetry Payload & Preliminary Model Verdict
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="itsm-hostname"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Observed Hostname (observed_hostname)
              </label>
              <input
                id="itsm-hostname"
                type="text"
                value={observedHostname}
                onChange={(e) => setObservedHostname(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="itsm-timestamp"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Event Timestamp (UTC ISO-8601)
              </label>
              <input
                id="itsm-timestamp"
                type="text"
                value={eventTimestampIso}
                onChange={(e) => setEventTimestampIso(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-xs font-mono tabular-nums text-slate-900 focus:border-slate-900 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="itsm-model-verdict"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Model Preliminary Verdict (model_verdict)
              </label>
              <select
                id="itsm-model-verdict"
                value={modelVerdict}
                onChange={(e) => setModelVerdict(e.target.value as ModelVerdict)}
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
              >
                <option value="BTP">BTP (Benign True Positive / Maintenance)</option>
                <option value="TP">TP (True Positive Threat)</option>
                <option value="FP">FP (False Positive)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="itsm-ticket"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Claimed Change Ticket (ticket_id)
              </label>
              <input
                id="itsm-ticket"
                type="text"
                value={claimedTicketId}
                onChange={(e) => setClaimedTicketId(e.target.value)}
                placeholder="e.g. CHG-2026-4109"
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="itsm-raw-log"
              className="block text-xs font-medium text-slate-700 mb-1"
            >
              Raw Untrusted Telemetry Log (wrapped in dynamic random nonce envelope)
            </label>
            <textarea
              id="itsm-raw-log"
              rows={5}
              value={rawLog}
              onChange={(e) => setRawLog(e.target.value)}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
            />
          </div>

          {formError && (
            <p className="text-xs text-rose-700" role="alert">
              {formError}
            </p>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>Wrap Nonce Envelope & Verify ITSM</span>
            </button>
          </div>
        </form>

        {/* Right: Deterministic Output */}
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-900 border-b border-slate-100 pb-3">
            02. Out-of-Process Deterministic Verdict & Nonce Envelope
          </h2>

          {!lastResult ? (
            <div className="py-10 text-center text-xs text-slate-500">
              Click “Wrap Nonce Envelope & Verify ITSM” to execute the out-of-process cross-check.
            </div>
          ) : (
            <div className="space-y-4">
              <div
                className={`rounded-md border p-4 space-y-2 ${
                  lastResult.escalated
                    ? 'bg-rose-50/70 border-rose-200 text-rose-950'
                    : 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-sm font-bold font-mono">
                    {lastResult.escalated ? (
                      <ShieldAlert className="h-4 w-4 text-rose-700 shrink-0" aria-hidden="true" />
                    ) : (
                      <ShieldCheck className="h-4 w-4 text-emerald-700 shrink-0" aria-hidden="true" />
                    )}
                    <span>{lastResult.finalVerdict}</span>
                  </div>
                  <span className="text-[11px] font-mono tabular-nums text-slate-700">
                    Decisions API: {lastResult.decisionsApiRoute} · {lastResult.decisionsLatencyMs}ms
                  </span>
                </div>
                <p className="text-xs leading-relaxed">{lastResult.reason}</p>
              </div>

              <div className="divide-y divide-slate-100 border border-slate-200 rounded-md">
                {lastResult.checks.map((chk) => (
                  <div key={chk.id} className="p-3 flex items-start gap-2.5 text-xs">
                    {chk.passed ? (
                      <CheckCircle2
                        className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5"
                        aria-hidden="true"
                      />
                    ) : (
                      <XCircle
                        className="h-4 w-4 text-rose-600 shrink-0 mt-0.5"
                        aria-hidden="true"
                      />
                    )}
                    <div className="space-y-0.5 min-w-0">
                      <div className="font-semibold text-slate-900">{chk.label}</div>
                      <div className="text-slate-600 break-words">{chk.detail}</div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-slate-700">
                    Generated Dynamic 16-Hex Nonce Envelope
                  </span>
                  <span className="font-mono tabular-nums text-slate-500">
                    nonce={lastResult.envelope.nonce}
                  </span>
                </div>
                <pre className="p-3 rounded-md bg-slate-900 text-slate-100 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap break-all">
                  {lastResult.envelope.envelopeText}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Enterprise ITSM Ground-Truth Change Control Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              Enterprise Ground-Truth ITSM Change Registry (Out-of-Process Source)
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Models have zero write access to this table; the external verifier validates BTP claims strictly against these records.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowAddTicket((v) => !v)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{showAddTicket ? 'Hide Form' : 'Register Change Window'}</span>
          </button>
        </div>

        {showAddTicket && (
          <form
            onSubmit={handleCreateTicket}
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 p-4 bg-slate-50 border border-slate-200 rounded-md items-end"
          >
            <div>
              <label htmlFor="new-ticket-id" className="block text-[11px] font-medium text-slate-700 mb-1">
                Ticket ID
              </label>
              <input
                id="new-ticket-id"
                type="text"
                value={newTicketId}
                onChange={(e) => setNewTicketId(e.target.value)}
                className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-mono"
              />
            </div>
            <div>
              <label htmlFor="new-ticket-host" className="block text-[11px] font-medium text-slate-700 mb-1">
                Authorized Hostname
              </label>
              <input
                id="new-ticket-host"
                type="text"
                value={newHostname}
                onChange={(e) => setNewHostname(e.target.value)}
                className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-mono"
              />
            </div>
            <div>
              <label htmlFor="new-ticket-start" className="block text-[11px] font-medium text-slate-700 mb-1">
                Window Start (UTC)
              </label>
              <input
                id="new-ticket-start"
                type="text"
                value={newStart}
                onChange={(e) => setNewStart(e.target.value)}
                className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-mono"
              />
            </div>
            <div>
              <label htmlFor="new-ticket-end" className="block text-[11px] font-medium text-slate-700 mb-1">
                Window End (UTC)
              </label>
              <input
                id="new-ticket-end"
                type="text"
                value={newEnd}
                onChange={(e) => setNewEnd(e.target.value)}
                className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-mono"
              />
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                aria-label="Change summary"
                value={newSummary}
                onChange={(e) => setNewSummary(e.target.value)}
                className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs"
                placeholder="Change summary"
              />
              <button
                type="submit"
                className="px-3 py-1.5 text-xs font-medium text-white bg-slate-900 rounded hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
              >
                Add
              </button>
            </div>
          </form>
        )}

        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                <th className="py-2.5 px-3 font-medium">Ticket ID (ticket_id)</th>
                <th className="py-2.5 px-3 font-medium">Authorized Host (hostname)</th>
                <th className="py-2.5 px-3 font-medium">Approved Window (approved_window)</th>
                <th className="py-2.5 px-3 font-medium">Change Summary</th>
                <th className="py-2.5 px-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {itsmTable.map((rec) => (
                <tr key={rec.ticketId} className="hover:bg-slate-50/60">
                  <td className="py-2.5 px-3 font-mono font-semibold text-slate-900 whitespace-nowrap">
                    {rec.ticketId}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-700 whitespace-nowrap">
                    {rec.hostname}
                  </td>
                  <td className="py-2.5 px-3 font-mono tabular-nums text-slate-600 whitespace-nowrap">
                    {rec.approvedWindowStart} ~ {rec.approvedWindowEnd}
                  </td>
                  <td className="py-2.5 px-3 text-slate-600">{rec.summary}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <StatusIndicator
                      compact
                      tone={
                        rec.status === 'APPROVED' || rec.status === 'IN_PROGRESS'
                          ? 'success'
                          : 'warning'
                      }
                      label={rec.status}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
