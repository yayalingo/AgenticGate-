import { useEffect, useState } from 'react';
import { Lock, RotateCcw, ShieldAlert, ShieldCheck } from 'lucide-react';
import type {
  BaselineLockEntry,
  HashLockVerdict,
  MCPToolDefinition,
} from '../lib/canonicalMcpLock';
import { RUG_PULL_PRESETS } from '../lib/seedData';
import { StatusIndicator } from './StatusIndicator';

interface McpHashLockLabProps {
  agentId: string;
  scope: string;
  tools: MCPToolDefinition[];
  baselines: BaselineLockEntry[];
  quarantinedToolNames: string[];
  lastVerdict: HashLockVerdict | null;
  onUpdateRuntimeTool: (tool: MCPToolDefinition) => void;
  onVerifyTool: (tool: MCPToolDefinition) => Promise<HashLockVerdict>;
  onResetBaselines: () => Promise<void>;
  onApplyRugPullPreset: (presetId: string) => Promise<HashLockVerdict>;
}

export function McpHashLockLab({
  agentId,
  scope,
  tools,
  baselines,
  quarantinedToolNames,
  lastVerdict,
  onUpdateRuntimeTool,
  onVerifyTool,
  onResetBaselines,
  onApplyRugPullPreset,
}: McpHashLockLabProps) {
  const [selectedToolName, setSelectedToolName] = useState<string>(
    tools[0]?.name ?? 'fetch_telemetry_logs'
  );
  const selectedTool =
    tools.find((t) => t.name === selectedToolName) ?? tools[0];

  const [draftDescription, setDraftDescription] = useState(
    selectedTool?.description ?? ''
  );
  const [draftSchemaText, setDraftSchemaText] = useState(
    JSON.stringify(selectedTool?.inputSchema ?? {}, null, 2)
  );
  const [draftReadOnly, setDraftReadOnly] = useState(
    Boolean(selectedTool?.annotations?.readOnlyHint)
  );
  const [draftDestructive, setDraftDestructive] = useState(
    Boolean(selectedTool?.annotations?.destructiveHint)
  );
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    if (!selectedTool) return;
    setDraftDescription(selectedTool.description);
    setDraftSchemaText(JSON.stringify(selectedTool.inputSchema, null, 2));
    setDraftReadOnly(Boolean(selectedTool.annotations?.readOnlyHint));
    setDraftDestructive(Boolean(selectedTool.annotations?.destructiveHint));
    setJsonError(null);
  }, [selectedTool]);

  if (!selectedTool) return null;

  const baselineRecord = baselines.find((b) => b.toolName === selectedTool.name);
  const isQuarantined = quarantinedToolNames.includes(selectedTool.name);

  const handleVerifyDraft = async () => {
    let parsedSchema: Record<string, unknown>;
    try {
      parsedSchema = JSON.parse(draftSchemaText);
      setJsonError(null);
    } catch {
      setJsonError('Invalid inputSchema JSON syntax. Check brackets and quotes.');
      return;
    }

    const updatedTool: MCPToolDefinition = {
      ...selectedTool,
      description: draftDescription,
      inputSchema: parsedSchema,
      annotations: {
        ...selectedTool.annotations,
        readOnlyHint: draftReadOnly,
        destructiveHint: draftDestructive,
      },
    };
    setVerifying(true);
    try {
      onUpdateRuntimeTool(updatedTool);
      await onVerifyTool(updatedTool);
    } finally {
      setVerifying(false);
    }
  };

  const handleTriggerPreset = async (presetId: string) => {
    const preset = RUG_PULL_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;
    setSelectedToolName(preset.targetToolName);
    setVerifying(true);
    try {
      await onApplyRugPullPreset(presetId);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Controls */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-500">
            <span>Bound Scope: ({agentId}, {scope})</span>
            <span aria-hidden="true">·</span>
            <span>Canonicalizer: Recursive Key Sort + Unicode NFC + SHA-256</span>
          </div>
          <h1 className="text-xl font-bold text-slate-900">
            CanonicalMCPHashLock — Runtime Tool Tamper Interception Lab
          </h1>
        </div>
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => onResetBaselines()}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Restore Clean Baselines & Unquarantine</span>
          </button>
        </div>
      </div>

      {/* Rug Pull Attack Presets Strip */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-900">
            Inject NHIMG MCP Rug Pull Attack Vectors
          </h2>
          <span className="text-xs text-slate-500">
            Simulates a remote MCP server silently mutating tool definitions after initial mount
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {RUG_PULL_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => handleTriggerPreset(preset.id)}
              className="text-left p-3.5 rounded-md border border-slate-200 bg-slate-50/60 hover:bg-slate-100 hover:border-slate-300 transition-colors cursor-pointer"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-rose-700">
                  {preset.label}
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {preset.targetToolName}
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                {preset.attackSummary}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Main Split: Tool Registry + Runtime Definition Editor & Diff */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Mounted Tools */}
        <div className="lg:col-span-4 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
            <h2 className="text-xs font-semibold text-slate-700">
              Mounted MCP Tools ({tools.length})
            </h2>
            <span className="text-[11px] font-mono text-slate-500">SHA-256 Lock</span>
          </div>
          <div className="divide-y divide-slate-100">
            {tools.map((tool) => {
              const base = baselines.find((b) => b.toolName === tool.name);
              const quarantined = quarantinedToolNames.includes(tool.name);
              const active = tool.name === selectedTool.name;
              return (
                <button
                  key={tool.name}
                  type="button"
                  onClick={() => setSelectedToolName(tool.name)}
                  className={`w-full text-left px-4 py-3.5 transition-colors cursor-pointer ${
                    active ? 'bg-slate-100/80' : 'hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-mono font-semibold text-slate-900 truncate">
                      {tool.name}
                    </span>
                    <StatusIndicator
                      compact
                      tone={quarantined ? 'danger' : 'success'}
                      label={quarantined ? 'Quarantined' : 'Locked'}
                    />
                  </div>
                  <div className="mt-1.5 text-[11px] font-mono tabular-nums text-slate-500 truncate">
                    Baseline: {base ? `${base.sha256.slice(0, 20)}…` : 'Unregistered'}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Inspector & Runtime Tamper Workbench */}
        <div className="lg:col-span-8 bg-white border border-slate-200 rounded-lg p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-100 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-mono font-bold text-slate-900">
                  {selectedTool.name}
                </h2>
                <StatusIndicator
                  tone={isQuarantined ? 'danger' : 'success'}
                  label={isQuarantined ? 'QUARANTINED_HASH_DRIFT' : 'BASELINE_LOCKED'}
                />
              </div>
              <p className="text-xs text-slate-500 mt-1 font-mono tabular-nums break-all">
                Baseline SHA-256: {baselineRecord?.sha256 ?? 'N/A'}
              </p>
            </div>
            <button
              type="button"
              onClick={handleVerifyDraft}
              disabled={verifying}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-md hover:bg-slate-800 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Lock className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{verifying ? 'Verifying...' : 'Run Out-of-Process Gate Check'}</span>
            </button>
          </div>

          {/* Verdict Banner */}
          {lastVerdict && lastVerdict.toolName === selectedTool.name && (
            <div
              className={`rounded-md border p-4 space-y-2 ${
                lastVerdict.allowed
                  ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                  : 'bg-rose-50/70 border-rose-200 text-rose-950'
              }`}
            >
              <div className="flex items-center gap-2 text-sm font-semibold">
                {lastVerdict.allowed ? (
                  <ShieldCheck className="h-4 w-4 text-emerald-700 shrink-0" aria-hidden="true" />
                ) : (
                  <ShieldAlert className="h-4 w-4 text-rose-700 shrink-0" aria-hidden="true" />
                )}
                <span>
                  {lastVerdict.allowed
                    ? 'Verified: Tool Invocation Permitted'
                    : `Out-of-Process Block & Quarantine (${lastVerdict.status})`}
                </span>
              </div>
              <p className="text-xs leading-relaxed">{lastVerdict.reason}</p>
              <div className="grid grid-cols-1 gap-1 pt-1 text-[11px] font-mono tabular-nums break-all">
                <div>Baseline SHA-256: {lastVerdict.baselineHash ?? 'NONE'}</div>
                <div>Runtime  SHA-256: {lastVerdict.runtimeHash}</div>
                {lastVerdict.diffFields.length > 0 && (
                  <div className="text-rose-800 font-semibold">
                    Drifted Fields (diffFields): {lastVerdict.diffFields.join(', ')}
                  </div>
                )}
                {lastVerdict.unicodeAnomalies.length > 0 && (
                  <div className="text-rose-800 font-semibold">
                    Unicode Anomalies: {lastVerdict.unicodeAnomalies.join('; ')}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Editable Runtime Fields */}
          <div className="space-y-4">
            <div>
              <label
                htmlFor="mcp-desc-input"
                className="block text-xs font-medium text-slate-700 mb-1.5"
              >
                Runtime description (edit text or inject zero-width characters to test hash drift; equivalent NFD/NFC forms normalize cleanly)
              </label>
              <textarea
                id="mcp-desc-input"
                rows={3}
                value={draftDescription}
                onChange={(e) => setDraftDescription(e.target.value)}
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="mcp-schema-input"
                className="block text-xs font-medium text-slate-700 mb-1.5"
              >
                Runtime inputSchema (key reordering is absorbed by canonicalization; adding or altering fields triggers SHA-256 quarantine)
              </label>
              <textarea
                id="mcp-schema-input"
                rows={8}
                value={draftSchemaText}
                onChange={(e) => setDraftSchemaText(e.target.value)}
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
              />
              {jsonError && (
                <p className="mt-1 text-xs text-rose-700" role="alert">
                  {jsonError}
                </p>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-6 pt-1">
              <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftReadOnly}
                  onChange={(e) => setDraftReadOnly(e.target.checked)}
                  className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
                />
                <span className="font-mono">annotations.readOnlyHint</span>
              </label>
              <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftDestructive}
                  onChange={(e) => setDraftDestructive(e.target.checked)}
                  className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
                />
                <span className="font-mono">annotations.destructiveHint</span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
