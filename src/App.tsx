import { useCallback, useEffect, useRef, useState } from 'react';
import {
  FileCode2,
  GitCommitHorizontal,
  LayoutDashboard,
  Lock,
  Menu,
  RotateCcw,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  CanonicalMCPHashLock,
  type BaselineLockEntry,
  type HashLockVerdict,
  type MCPToolDefinition,
} from './lib/canonicalMcpLock';
import {
  TrajectoryForensicsLedger,
  type ChainVerificationReport,
  type LedgerEntry,
} from './lib/forensicsLedger';
import {
  verifySocVerdictWithItsm,
  type ITSMChangeRecord,
  type ModelVerdict,
  type SocVerificationResult,
} from './lib/itsmVerifier';
import {
  DEFAULT_AGENT_ID,
  DEFAULT_SCOPE,
  RUG_PULL_PRESETS,
  SEEDED_ITSM_RECORDS,
  SEEDED_MCP_TOOLS,
  SOC_SCENARIO_PRESETS,
} from './lib/seedData';
import {
  GatewayOverview,
  type EndToEndScenarioId,
  type NavTab,
} from './components/GatewayOverview';
import { McpHashLockLab } from './components/McpHashLockLab';
import { ItsmVerifierLab } from './components/ItsmVerifierLab';
import { ForensicsLedgerView } from './components/ForensicsLedgerView';
import { PythonReferenceView } from './components/PythonReferenceView';

const NAV_ITEMS: Array<{
  id: NavTab;
  label: string;
  sublabel: string;
  icon: typeof LayoutDashboard;
}> = [
  {
    id: 'overview',
    label: 'Control Plane & Loop',
    sublabel: 'Agentic V2 Pipeline',
    icon: LayoutDashboard,
  },
  {
    id: 'mcp-lock',
    label: 'MCP Hash Lock',
    sublabel: 'CanonicalMCPHashLock',
    icon: Lock,
  },
  {
    id: 'itsm-verify',
    label: 'Nonce & ITSM Verifier',
    sublabel: 'verify_soc_verdict_with_itsm',
    icon: ShieldCheck,
  },
  {
    id: 'forensics',
    label: 'Forensics Ledger',
    sublabel: 'TrajectoryForensicsLedger',
    icon: GitCommitHorizontal,
  },
  {
    id: 'python-code',
    label: 'Python 3.12 Source',
    sublabel: 'Reference Implementation',
    icon: FileCode2,
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [ready, setReady] = useState(false);

  const hashLockRef = useRef(new CanonicalMCPHashLock());
  const ledgerRef = useRef(new TrajectoryForensicsLedger());
  const trustedEntriesRef = useRef<LedgerEntry[]>([]);

  const [runtimeTools, setRuntimeTools] = useState<MCPToolDefinition[]>(() =>
    structuredClone(SEEDED_MCP_TOOLS)
  );
  const [baselines, setBaselines] = useState<BaselineLockEntry[]>([]);
  const [quarantinedToolNames, setQuarantinedToolNames] = useState<string[]>([]);
  const [lastHashVerdict, setLastHashVerdict] = useState<HashLockVerdict | null>(null);

  const [itsmTable, setItsmTable] = useState<ITSMChangeRecord[]>(() =>
    structuredClone(SEEDED_ITSM_RECORDS)
  );
  const [lastItsmResult, setLastItsmResult] = useState<SocVerificationResult | null>(null);

  const [ledgerEntries, setLedgerEntries] = useState<LedgerEntry[]>([]);
  const [chainReport, setChainReport] = useState<ChainVerificationReport | null>(null);
  const [hasTamper, setHasTamper] = useState(false);

  const syncLedgerState = useCallback(async (entries: LedgerEntry[], tampered = false) => {
    setLedgerEntries(entries);
    if (!tampered) {
      trustedEntriesRef.current = entries.map((e) => ({ ...e }));
    }
    setHasTamper(tampered);
    const report = await TrajectoryForensicsLedger.verifyChain(entries);
    setChainReport(report);
  }, []);

  const initializeWorkspace = useCallback(async () => {
    const lock = new CanonicalMCPHashLock();
    const freshTools = structuredClone(SEEDED_MCP_TOOLS);
    const bound = await lock.bindBaseline(DEFAULT_AGENT_ID, DEFAULT_SCOPE, freshTools);
    hashLockRef.current = lock;
    setRuntimeTools(freshTools);
    setBaselines(bound);
    setQuarantinedToolNames([]);
    setLastHashVerdict(null);
    setItsmTable(structuredClone(SEEDED_ITSM_RECORDS));
    setLastItsmResult(null);

    const ledger = new TrajectoryForensicsLedger();
    await ledger.appendStep({
      phase: 'MCP_HASH_LOCK',
      agentId: DEFAULT_AGENT_ID,
      hypothesis: `Bind canonical SHA-256 baseline locks for ${bound.length} MCP tools under (${DEFAULT_AGENT_ID}, ${DEFAULT_SCOPE})`,
      toolName: 'CanonicalMCPHashLock.bind_baseline',
      toolArgs: { scope: DEFAULT_SCOPE, tool_count: bound.length },
      resultSummary: `Completed Unicode NFC normalization and key-sorted baseline locks for ${bound.length} tools`,
      verdict: 'BASELINE_LOCKED',
      complianceRef: 'OWASP-Agentic-V2;NHIMG-MCP-2026-11-12',
    });
    await ledger.appendStep({
      phase: 'DECISIONS_PRECHECK',
      agentId: DEFAULT_AGENT_ID,
      hypothesis: 'Initialize Decisions API zero-output-cost closed-set routing taxonomy',
      toolName: 'decisions.create',
      toolArgs: {
        taxonomy: ['CLOSE_BENIGN_MAINTENANCE', 'ESCALATE_INCIDENT', 'BLOCK_LOG_INJECTION'],
      },
      resultSummary: 'Closed-set precheck router ready (~11ms avg latency)',
      verdict: 'READY',
      complianceRef: 'Decisions-API-2026-11-11',
    });
    ledgerRef.current = ledger;
    await syncLedgerState(ledger.getEntries(), false);
    setReady(true);
  }, [syncLedgerState]);

  useEffect(() => {
    void initializeWorkspace();
  }, [initializeWorkspace]);

  const appendLiveStep = useCallback(
    async (
      stepInput: Parameters<TrajectoryForensicsLedger['appendStep']>[0]
    ) => {
      if (hasTamper) {
        ledgerRef.current = new TrajectoryForensicsLedger(trustedEntriesRef.current);
      }
      await ledgerRef.current.appendStep(stepInput);
      await syncLedgerState(ledgerRef.current.getEntries(), false);
    },
    [hasTamper, syncLedgerState]
  );

  const handleVerifyTool = useCallback(
    async (tool: MCPToolDefinition): Promise<HashLockVerdict> => {
      const verdict = await hashLockRef.current.verifyAndGate(
        DEFAULT_AGENT_ID,
        DEFAULT_SCOPE,
        tool
      );
      setLastHashVerdict(verdict);
      const qNames = SEEDED_MCP_TOOLS.map((t) => t.name).filter((name) =>
        hashLockRef.current.isQuarantined(DEFAULT_AGENT_ID, DEFAULT_SCOPE, name)
      );
      setQuarantinedToolNames(qNames);

      await appendLiveStep({
        phase: 'MCP_HASH_LOCK',
        agentId: DEFAULT_AGENT_ID,
        hypothesis: `Verify canonical SHA-256 baseline outside model process before calling ${tool.name}`,
        toolName: tool.name,
        toolArgs: { scope: DEFAULT_SCOPE, diff_fields: verdict.diffFields },
        resultSummary: verdict.reason,
        verdict: verdict.status,
        complianceRef: 'OWASP-Agentic-V2;NHIMG-MCP-2026-11-12',
      });

      return verdict;
    },
    [appendLiveStep]
  );

  const handleApplyRugPullPreset = useCallback(
    async (presetId: string): Promise<HashLockVerdict> => {
      const preset = RUG_PULL_PRESETS.find((p) => p.id === presetId) ?? RUG_PULL_PRESETS[0];
      const baseTool =
        SEEDED_MCP_TOOLS.find((t) => t.name === preset.targetToolName) ??
        SEEDED_MCP_TOOLS[0];
      const mutated = preset.mutate(baseTool);
      setRuntimeTools((prev) =>
        prev.map((t) => (t.name === mutated.name ? mutated : t))
      );
      return handleVerifyTool(mutated);
    },
    [handleVerifyTool]
  );

  const handleResetBaselines = useCallback(async () => {
    const freshTools = structuredClone(SEEDED_MCP_TOOLS);
    const bound = await hashLockRef.current.bindBaseline(
      DEFAULT_AGENT_ID,
      DEFAULT_SCOPE,
      freshTools
    );
    setRuntimeTools(freshTools);
    setBaselines(bound);
    setQuarantinedToolNames([]);
    setLastHashVerdict(null);
    await appendLiveStep({
      phase: 'MCP_HASH_LOCK',
      agentId: DEFAULT_AGENT_ID,
      hypothesis: 'Operator restored trusted MCP baseline definitions and cleared quarantine state',
      toolName: 'CanonicalMCPHashLock.bind_baseline',
      toolArgs: { scope: DEFAULT_SCOPE, reset: true },
      resultSummary: `Re-locked canonical SHA-256 hashes for ${bound.length} tools`,
      verdict: 'BASELINE_LOCKED',
      complianceRef: 'OWASP-Agentic-V2',
    });
  }, [appendLiveStep]);

  const handleVerifyItsm = useCallback(
    async (params: {
      modelVerdict: ModelVerdict;
      claimedTicketId: string | null;
      observedHostname: string;
      eventTimestampIso: string;
      rawLog: string;
    }): Promise<SocVerificationResult> => {
      const result = verifySocVerdictWithItsm({
        ...params,
        itsmTable,
      });
      setLastItsmResult(result);

      await appendLiveStep({
        phase: 'NONCE_ENVELOPE',
        agentId: DEFAULT_AGENT_ID,
        hypothesis: 'Wrap untrusted telemetry log inside dynamic 16-hex random nonce envelope',
        toolName: 'wrap_untrusted_telemetry',
        toolArgs: {
          nonce: result.envelope.nonce,
          breakout_detected: result.envelope.breakoutAttemptDetected,
        },
        resultSummary: `Sealed telemetry inside <untrusted_telemetry_${result.envelope.nonce}>`,
        verdict: result.envelope.breakoutAttemptDetected
          ? 'ENVELOPE_BREAKOUT_STRIPPED'
          : 'ENVELOPE_SEALED',
        complianceRef: 'OWASP-Agentic-V2',
      });

      await appendLiveStep({
        phase: 'ITSM_VERIFICATION',
        agentId: DEFAULT_AGENT_ID,
        hypothesis: `Model output ${params.modelVerdict}; cross-verify enterprise ITSM change table out-of-process`,
        toolName: 'verify_soc_verdict_with_itsm',
        toolArgs: {
          claimed_ticket_id: params.claimedTicketId,
          observed_hostname: params.observedHostname,
          decisions_route: result.decisionsApiRoute,
        },
        resultSummary: result.reason,
        verdict: result.finalVerdict,
        complianceRef: 'DeepMind#143922037276975814;Snowflake#ASHREQ-8175',
      });

      return result;
    },
    [appendLiveStep, itsmTable]
  );

  const handleRunEndToEnd = useCallback(
    async (scenarioId: EndToEndScenarioId) => {
      if (scenarioId === 'rug_pull_block') {
        await appendLiveStep({
          phase: 'DECISIONS_PRECHECK',
          agentId: DEFAULT_AGENT_ID,
          hypothesis: 'Decisions API precheck routes telemetry fetch tool invocation',
          toolName: 'decisions.create',
          toolArgs: { target_tool: 'fetch_telemetry_logs' },
          resultSummary: 'Precheck permitted transition to out-of-process MCP gate',
          verdict: 'ROUTE_TO_TOOL_GATE',
          complianceRef: 'Decisions-API-2026-11-11',
        });
        await handleApplyRugPullPreset('description_exfil');
        return;
      }

      const cleanTool = SEEDED_MCP_TOOLS[0];
      await handleVerifyTool(cleanTool);

      const preset =
        scenarioId === 'watchtower_forged_btp'
          ? SOC_SCENARIO_PRESETS[0]
          : SOC_SCENARIO_PRESETS[3];

      await handleVerifyItsm({
        modelVerdict: preset.modelVerdict,
        claimedTicketId: preset.claimedTicketId,
        observedHostname: preset.observedHostname,
        eventTimestampIso: preset.eventTimestampIso,
        rawLog: preset.rawLog,
      });
    },
    [appendLiveStep, handleApplyRugPullPreset, handleVerifyItsm, handleVerifyTool]
  );

  const handleTamperLedgerStep = useCallback(
    async (stepIndex: number) => {
      const tampered = ledgerEntries.map((entry) =>
        entry.stepIndex === stepIndex
          ? {
              ...entry,
              verdict:
                entry.verdict === 'BTP_VERIFIED_WITH_ITSM'
                  ? 'TP_CONFIRMED'
                  : 'BTP_VERIFIED_WITH_ITSM',
              resultSummary: '[TAMPERED BY ADVERSARY] Post-hoc verdict modification to conceal intrusion',
            }
          : entry
      );
      await syncLedgerState(tampered, true);
    },
    [ledgerEntries, syncLedgerState]
  );

  const handleRestoreLedger = useCallback(async () => {
    const clean = trustedEntriesRef.current.map((e) => ({ ...e }));
    ledgerRef.current = new TrajectoryForensicsLedger(clean);
    await syncLedgerState(clean, false);
  }, [syncLedgerState]);

  const handleVerifyChainManual = useCallback(async () => {
    const report = await TrajectoryForensicsLedger.verifyChain(ledgerEntries);
    setChainReport(report);
  }, [ledgerEntries]);

  const activeNavMeta = NAV_ITEMS.find((n) => n.id === activeTab) ?? NAV_ITEMS[0];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col lg:flex-row">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:w-[280px] lg:flex-col lg:fixed lg:inset-y-0 bg-white border-r border-slate-200 z-20">
        <div className="h-14 px-5 border-b border-slate-200 flex items-center">
          <span className="text-base font-bold tracking-tight text-slate-900 whitespace-nowrap">
            AgenticGate V2
          </span>
        </div>

        <nav className="flex-1 p-3 space-y-1" aria-label="Primary Navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                aria-current={active ? 'page' : undefined}
                onClick={() => setActiveTab(item.id)}
                className={`w-full text-left px-3 py-2.5 rounded-md flex items-start gap-3 transition-colors cursor-pointer ${
                  active
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <Icon
                  className={`h-4 w-4 mt-0.5 shrink-0 ${
                    active ? 'text-white' : 'text-slate-500'
                  }`}
                  aria-hidden="true"
                />
                <div className="min-w-0">
                  <div className="text-xs font-semibold truncate">{item.label}</div>
                  <div
                    className={`text-[11px] font-mono truncate mt-0.5 ${
                      active ? 'text-slate-300' : 'text-slate-500'
                    }`}
                  >
                    {item.sublabel}
                  </div>
                </div>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 text-[11px] text-slate-500 space-y-1 font-mono">
          <div className="truncate">Agent: {DEFAULT_AGENT_ID}</div>
          <div className="truncate">Scope: {DEFAULT_SCOPE}</div>
        </div>
      </aside>

      {/* Mobile Slide-Over Navigation */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-900/40"
            onClick={() => setMobileNavOpen(false)}
            aria-hidden="true"
          />
          <aside className="relative w-72 max-w-full bg-white h-full border-r border-slate-200 p-4 flex flex-col justify-between z-50">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-slate-200">
                <span className="text-base font-bold text-slate-900">AgenticGate V2</span>
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(false)}
                  aria-label="Close navigation menu"
                  className="p-2 rounded-md text-slate-600 hover:bg-slate-100 cursor-pointer"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              <nav className="mt-4 space-y-1" aria-label="Mobile Navigation">
                {NAV_ITEMS.map((item) => {
                  const Icon = item.icon;
                  const active = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveTab(item.id);
                        setMobileNavOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2.5 rounded-md flex items-center gap-3 cursor-pointer ${
                        active
                          ? 'bg-slate-900 text-white'
                          : 'text-slate-700 hover:bg-slate-100'
                      }`}
                    >
                      <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                      <span className="text-sm font-medium">{item.label}</span>
                    </button>
                  );
                })}
              </nav>
            </div>
          </aside>
        </div>
      )}

      {/* Main Content Shell */}
      <div className="flex-1 lg:pl-[280px] flex flex-col min-w-0">
        {/* Top Bar Contract */}
        <header className="h-14 bg-white border-b border-slate-200 px-4 sm:px-6 flex items-center justify-between gap-4 sticky top-0 z-10">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileNavOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-2 -ml-2 rounded-md text-slate-600 hover:bg-slate-100 cursor-pointer"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-2 text-sm min-w-0 truncate">
              <span className="text-slate-500 hidden sm:inline whitespace-nowrap">
                OWASP Agentic V2
              </span>
              <span className="text-slate-300 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <span className="font-semibold text-slate-900 truncate">
                {activeNavMeta.label}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => void initializeWorkspace()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Reset Sandbox</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1360px] w-full mx-auto">
          {!ready ? (
            <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-sm text-slate-500">
              Initializing SHA-256 baseline hash locks and trajectory forensics ledger...
            </div>
          ) : activeTab === 'overview' ? (
            <GatewayOverview
              agentId={DEFAULT_AGENT_ID}
              scope={DEFAULT_SCOPE}
              baselines={baselines}
              quarantinedToolNames={quarantinedToolNames}
              lastHashVerdict={lastHashVerdict}
              lastItsmResult={lastItsmResult}
              ledgerEntries={ledgerEntries}
              chainReport={chainReport}
              onRunEndToEnd={handleRunEndToEnd}
              onNavigate={setActiveTab}
            />
          ) : activeTab === 'mcp-lock' ? (
            <McpHashLockLab
              agentId={DEFAULT_AGENT_ID}
              scope={DEFAULT_SCOPE}
              tools={runtimeTools}
              baselines={baselines}
              quarantinedToolNames={quarantinedToolNames}
              lastVerdict={lastHashVerdict}
              onUpdateRuntimeTool={(updated) =>
                setRuntimeTools((prev) =>
                  prev.map((t) => (t.name === updated.name ? updated : t))
                )
              }
              onVerifyTool={handleVerifyTool}
              onResetBaselines={handleResetBaselines}
              onApplyRugPullPreset={handleApplyRugPullPreset}
            />
          ) : activeTab === 'itsm-verify' ? (
            <ItsmVerifierLab
              itsmTable={itsmTable}
              lastResult={lastItsmResult}
              onAddItsmRecord={(record) =>
                setItsmTable((prev) => [record, ...prev])
              }
              onVerifyVerdict={handleVerifyItsm}
            />
          ) : activeTab === 'forensics' ? (
            <ForensicsLedgerView
              entries={ledgerEntries}
              chainReport={chainReport}
              hasTamper={hasTamper}
              onVerifyChain={handleVerifyChainManual}
              onTamperStep={handleTamperLedgerStep}
              onRestoreLedger={handleRestoreLedger}
            />
          ) : (
            <PythonReferenceView />
          )}
        </main>
      </div>
    </div>
  );
}
