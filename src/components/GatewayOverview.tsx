import { useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  FileCode2,
  GitCommitHorizontal,
  Lock,
  Play,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { BaselineLockEntry, HashLockVerdict } from '../lib/canonicalMcpLock';
import type { ChainVerificationReport, LedgerEntry } from '../lib/forensicsLedger';
import type { SocVerificationResult } from '../lib/itsmVerifier';
import { StatusIndicator } from './StatusIndicator';

export type NavTab = 'overview' | 'mcp-lock' | 'itsm-verify' | 'forensics' | 'python-code';

export type EndToEndScenarioId =
  | 'rug_pull_block'
  | 'watchtower_forged_btp'
  | 'nominal_authorized_btp';

interface GatewayOverviewProps {
  agentId: string;
  scope: string;
  baselines: BaselineLockEntry[];
  quarantinedToolNames: string[];
  lastHashVerdict: HashLockVerdict | null;
  lastItsmResult: SocVerificationResult | null;
  ledgerEntries: LedgerEntry[];
  chainReport: ChainVerificationReport | null;
  onRunEndToEnd: (scenarioId: EndToEndScenarioId) => Promise<void>;
  onNavigate: (tab: NavTab) => void;
}

const E2E_SCENARIOS: Array<{
  id: EndToEndScenarioId;
  title: string;
  targetThreat: string;
  expectedOutcome: string;
}> = [
  {
    id: 'rug_pull_block',
    title: 'Drill 1: Runtime MCP Rug Pull Tampering',
    targetThreat: 'fetch_telemetry_logs description poisoned with credential exfiltration prompt',
    expectedOutcome: 'SHA-256 hash drift triggers out-of-process quarantine and halts tool execution',
  },
  {
    id: 'watchtower_forged_btp',
    title: 'Drill 2: Poisoning the Watchtower Forged Ticket',
    targetThreat: 'Log payload injects fake CHG-2026-99412 to trick AI SOC into classifying as BTP',
    expectedOutcome: 'Random nonce envelope isolates log; ITSM mismatch escalates to TP_ESCALATED_LOG_INJECTION_SUSPECTED',
  },
  {
    id: 'nominal_authorized_btp',
    title: 'Drill 3: Authorized Maintenance Window Pass',
    targetThreat: 'k8s-worker-eu-04 upgraded inside CHG-2026-4109 maintenance window',
    expectedOutcome: 'MCP hash lock and ITSM tuple both pass; BTP verified and appended to ledger',
  },
];

export function GatewayOverview({
  agentId,
  scope,
  baselines,
  quarantinedToolNames,
  lastHashVerdict,
  lastItsmResult,
  ledgerEntries,
  chainReport,
  onRunEndToEnd,
  onNavigate,
}: GatewayOverviewProps) {
  const [selectedScenario, setSelectedScenario] =
    useState<EndToEndScenarioId>('watchtower_forged_btp');
  const [running, setRunning] = useState(false);

  const handleRun = async () => {
    setRunning(true);
    try {
      await onRunEndToEnd(selectedScenario);
    } finally {
      setRunning(false);
    }
  };

  const recentSteps = ledgerEntries.slice(-4);

  return (
    <div className="space-y-8">
      {/* Intro & Core Architecture Thesis */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
          <div className="max-w-3xl space-y-2.5">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 font-mono tabular-nums">
              <span>OWASP Securing Agentic Applications V2 (2026-11-10)</span>
              <span aria-hidden="true">·</span>
              <span>NHIMG MCP Rug Pull Guide (2026-11-12)</span>
              <span aria-hidden="true">·</span>
              <span>Decisions API (2026-11-11)</span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">
              Out-of-Process Deterministic Interception Gateway & Forensics Control Plane
            </h1>
            <p className="text-sm leading-relaxed text-slate-600">
              Input-side prompt sanitization alone cannot stop silent runtime tool mutations (Rug Pulls) or forged change tickets inside logs deceiving AI SOC triage (Poisoning the Watchtower).
              This workbench enforces three pure deterministic mechanisms outside the model process: a canonical SHA-256 hash lock, dynamic nonce envelopes with ITSM cross-verification, and a chained trajectory forensics ledger.
            </p>
          </div>
          <div className="shrink-0 flex flex-col sm:flex-row lg:flex-col gap-2.5">
            <button
              type="button"
              onClick={() => onNavigate('python-code')}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <FileCode2 className="h-4 w-4 text-slate-500" aria-hidden="true" />
              <span>View Python 3.12 Source</span>
            </button>
          </div>
        </div>
      </section>

      {/* 4-Column Operational KPI Strip */}
      <section aria-label="Gateway Live Security Metrics" className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Locked MCP Tools</span>
            <Lock className="h-4 w-4 text-slate-400" aria-hidden="true" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-900">
            {baselines.length}
          </div>
          <div className="text-xs text-slate-500 font-mono truncate">
            {agentId} · {scope}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Quarantined Tools (Rug Pull)</span>
            <ShieldAlert className="h-4 w-4 text-slate-400" aria-hidden="true" />
          </div>
          <div className="flex items-baseline gap-2.5">
            <span className="text-2xl font-bold font-mono tabular-nums text-slate-900">
              {quarantinedToolNames.length}
            </span>
            <StatusIndicator
              compact
              tone={quarantinedToolNames.length > 0 ? 'danger' : 'success'}
              label={quarantinedToolNames.length > 0 ? 'Quarantine Active' : 'Baseline Intact'}
            />
          </div>
          <div className="text-xs text-slate-500 truncate">
            {quarantinedToolNames.length > 0
              ? `Blocked: ${quarantinedToolNames.join(', ')}`
              : 'All mounted tool SHA-256 digests match'}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Latest ITSM Deterministic Verdict</span>
            <ShieldCheck className="h-4 w-4 text-slate-400" aria-hidden="true" />
          </div>
          <div className="pt-0.5">
            {lastItsmResult ? (
              <StatusIndicator
                tone={lastItsmResult.escalated ? 'danger' : 'success'}
                label={lastItsmResult.finalVerdict}
              />
            ) : (
              <StatusIndicator tone="neutral" label="Awaiting Cross-Check" />
            )}
          </div>
          <div className="text-xs text-slate-500 font-mono tabular-nums">
            {lastItsmResult
              ? `Nonce: ${lastItsmResult.envelope.nonce} · ${lastItsmResult.decisionsLatencyMs}ms`
              : '16-hex dynamic nonce isolation ready'}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Forensics Ledger Steps</span>
            <GitCommitHorizontal className="h-4 w-4 text-slate-400" aria-hidden="true" />
          </div>
          <div className="flex items-baseline gap-2.5">
            <span className="text-2xl font-bold font-mono tabular-nums text-slate-900">
              {ledgerEntries.length}
            </span>
            <StatusIndicator
              compact
              tone={chainReport?.valid === false ? 'danger' : 'success'}
              label={chainReport?.valid === false ? 'Chain Broken' : 'SHA-256 Valid'}
            />
          </div>
          <div className="text-xs text-slate-500 font-mono truncate">
            DeepMind #143922037276975814 · ASHREQ-8175
          </div>
        </div>
      </section>

      {/* Interactive End-to-End Agent Core Loop Simulator */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-100 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              01. End-to-End Agent Core Loop Simulation
            </h2>
            <p className="text-sm text-slate-600 mt-0.5">
              Select an adversarial or nominal payload to watch Decisions API precheck routing, MCP hash locking, nonce isolation, and ITSM verification execute in sequence.
            </p>
          </div>
          <button
            type="button"
            onClick={handleRun}
            disabled={running}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Play className="h-4 w-4" aria-hidden="true" />
            <span>{running ? 'Running...' : 'Run Full Gateway Loop'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {E2E_SCENARIOS.map((sc) => {
            const active = selectedScenario === sc.id;
            return (
              <button
                key={sc.id}
                type="button"
                onClick={() => setSelectedScenario(sc.id)}
                className={`text-left p-4 rounded-md border transition-colors cursor-pointer ${
                  active
                    ? 'border-slate-900 bg-slate-50'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <div className="text-sm font-semibold text-slate-900">{sc.title}</div>
                <div className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                  Payload: {sc.targetThreat}
                </div>
                <div className="text-xs text-slate-500 mt-2 pt-2 border-t border-slate-200/80">
                  Expected: {sc.expectedOutcome}
                </div>
              </button>
            );
          })}
        </div>

        {/* Live 4-Stage Pipeline Readout */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">
              Latest Gateway Execution Trajectory (Most Recent {recentSteps.length} Steps)
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('forensics')}
              className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-slate-900 cursor-pointer"
            >
              <span>Open Full Forensics Ledger</span>
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>

          <div className="overflow-x-auto border border-slate-200 rounded-md">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-600">
                  <th className="py-2.5 px-3 font-medium">Step</th>
                  <th className="py-2.5 px-3 font-medium">Control Phase</th>
                  <th className="py-2.5 px-3 font-medium">Tool / Function</th>
                  <th className="py-2.5 px-3 font-medium">Execution Summary</th>
                  <th className="py-2.5 px-3 font-medium">Verdict</th>
                  <th className="py-2.5 px-3 font-medium text-right">Entry SHA-256</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {recentSteps.map((step) => {
                  const isBlocked =
                    step.verdict.includes('QUARANTINED') ||
                    step.verdict.includes('ESCALATED') ||
                    step.verdict.includes('BLOCK');
                  return (
                    <tr key={step.stepIndex} className="hover:bg-slate-50/70">
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-700">
                        #{step.stepIndex}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-700 whitespace-nowrap">
                        {step.phase}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-900 whitespace-nowrap">
                        {step.toolName}
                      </td>
                      <td className="py-2.5 px-3 text-slate-600 max-w-md truncate">
                        {step.resultSummary}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <StatusIndicator
                          compact
                          tone={isBlocked ? 'danger' : 'success'}
                          label={step.verdict}
                        />
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-slate-500 text-right whitespace-nowrap">
                        {step.entryHash.slice(0, 12)}…
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Three Mechanisms Deep-Dive Navigation Cards */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="space-y-2">
            <div className="text-xs font-mono text-slate-500">Mechanism 01 · CanonicalMCPHashLock</div>
            <h3 className="text-base font-semibold text-slate-900">
              Canonical MCP Definition Hash Lock
            </h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Extracts name, description, inputSchema, and annotations, recursively sorts keys, applies Unicode NFC normalization, and binds SHA-256 digests by (agent_id, scope).
            </p>
            {lastHashVerdict && (
              <div className="pt-1 text-xs font-mono text-slate-500">
                Latest check: {lastHashVerdict.toolName} → {lastHashVerdict.status}
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => onNavigate('mcp-lock')}
            className="inline-flex items-center justify-between w-full px-3 py-2 text-xs font-medium text-slate-800 bg-slate-50 border border-slate-200 rounded-md hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <span>Open Rug Pull Defense Lab</span>
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="space-y-2">
            <div className="text-xs font-mono text-slate-500">Mechanism 02 · verify_soc_verdict_with_itsm</div>
            <h3 className="text-base font-semibold text-slate-900">
              Nonce Envelope & ITSM Verification
            </h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Wraps raw telemetry inside a per-investigation 16-hex random nonce tag and cross-checks every model BTP verdict against real ITSM (ticket_id, hostname, approved_window) records.
            </p>
            {lastItsmResult && (
              <div className="pt-1 text-xs font-mono text-slate-500">
                Latest verdict: {lastItsmResult.finalVerdict}
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => onNavigate('itsm-verify')}
            className="inline-flex items-center justify-between w-full px-3 py-2 text-xs font-medium text-slate-800 bg-slate-50 border border-slate-200 rounded-md hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <span>Open Watchtower Verifier Lab</span>
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="space-y-2">
            <div className="text-xs font-mono text-slate-500">Mechanism 03 · TrajectoryForensicsLedger</div>
            <h3 className="text-base font-semibold text-slate-900">
              Chained SHA-256 Forensics Ledger
            </h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Hashes every reasoning hypothesis, tool call payload, and gateway verdict into a continuous SHA-256 chain supporting structured replay and pinpoint tamper detection.
            </p>
            <div className="pt-1 flex items-center gap-1.5 text-xs font-mono text-emerald-700">
              <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{ledgerEntries.length} cryptographic steps recorded</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('forensics')}
            className="inline-flex items-center justify-between w-full px-3 py-2 text-xs font-medium text-slate-800 bg-slate-50 border border-slate-200 rounded-md hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <span>Open Forensics Replay & Audit</span>
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>
      </section>
    </div>
  );
}
