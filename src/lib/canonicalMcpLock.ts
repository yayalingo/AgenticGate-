export interface MCPToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  [key: string]: unknown;
}

export interface MCPToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: MCPToolAnnotations;
}

export interface BaselineLockEntry {
  scopeKey: string;
  agentId: string;
  scope: string;
  toolName: string;
  sha256: string;
  canonicalJson: string;
  lockedAt: string;
}

export type HashLockStatus =
  | 'VERIFIED'
  | 'QUARANTINED_HASH_DRIFT'
  | 'UNREGISTERED_TOOL';

export interface HashLockVerdict {
  allowed: boolean;
  status: HashLockStatus;
  scopeKey: string;
  toolName: string;
  baselineHash: string | null;
  runtimeHash: string;
  canonicalBaseline: string | null;
  canonicalRuntime: string;
  diffFields: Array<'name' | 'description' | 'inputSchema' | 'annotations'>;
  unicodeAnomalies: string[];
  reason: string;
}

const INVISIBLE_OR_BIDI_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

export function detectUnicodeAnomalies(text: string): string[] {
  const findings: string[] = [];
  const matches = text.match(INVISIBLE_OR_BIDI_RE);
  if (matches && matches.length > 0) {
    const codePoints = Array.from(new Set(matches)).map(
      (ch) => `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`
    );
    findings.push(`Detected hidden or bidirectional control characters: ${codePoints.join(', ')}`);
  }
  if (text !== text.normalize('NFC')) {
    findings.push('String is not in Unicode NFC canonical form (homoglyph or combining character drift risk)');
  }
  return findings;
}

export function canonicalizeValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return value.normalize('NFC');
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeValue(item));
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0
    );
    const out: Record<string, unknown> = {};
    for (const k of sortedKeys) {
      const normalizedKey = k.normalize('NFC');
      if (record[k] !== undefined) {
        out[normalizedKey] = canonicalizeValue(record[k]);
      }
    }
    return out;
  }
  return value;
}

export function extractCanonicalToolObject(tool: MCPToolDefinition): Record<string, unknown> {
  return canonicalizeValue({
    annotations: tool.annotations ?? {},
    description: tool.description,
    inputSchema: tool.inputSchema,
    name: tool.name,
  }) as Record<string, unknown>;
}

export function canonicalizeToolDefinition(tool: MCPToolDefinition): string {
  return JSON.stringify(extractCanonicalToolObject(tool));
}

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function buildScopeKey(agentId: string, scope: string): string {
  return `${agentId.normalize('NFC')}::${scope.normalize('NFC')}`;
}

export class CanonicalMCPHashLock {
  private baselines = new Map<string, Map<string, BaselineLockEntry>>();
  private quarantinedTools = new Set<string>();

  async bindBaseline(
    agentId: string,
    scope: string,
    tools: MCPToolDefinition[],
    lockedAt = new Date().toISOString()
  ): Promise<BaselineLockEntry[]> {
    const scopeKey = buildScopeKey(agentId, scope);
    const toolMap = new Map<string, BaselineLockEntry>();
    const entries: BaselineLockEntry[] = [];

    for (const tool of tools) {
      const canonicalJson = canonicalizeToolDefinition(tool);
      const sha256 = await sha256Hex(canonicalJson);
      const entry: BaselineLockEntry = {
        scopeKey,
        agentId,
        scope,
        toolName: tool.name.normalize('NFC'),
        sha256,
        canonicalJson,
        lockedAt,
      };
      toolMap.set(entry.toolName, entry);
      entries.push(entry);
      this.quarantinedTools.delete(`${scopeKey}::${entry.toolName}`);
    }

    this.baselines.set(scopeKey, toolMap);
    return entries;
  }

  getBaselines(agentId: string, scope: string): BaselineLockEntry[] {
    const scopeKey = buildScopeKey(agentId, scope);
    const map = this.baselines.get(scopeKey);
    return map ? Array.from(map.values()) : [];
  }

  isQuarantined(agentId: string, scope: string, toolName: string): boolean {
    return this.quarantinedTools.has(
      `${buildScopeKey(agentId, scope)}::${toolName.normalize('NFC')}`
    );
  }

  async verifyAndGate(
    agentId: string,
    scope: string,
    runtimeTool: MCPToolDefinition
  ): Promise<HashLockVerdict> {
    const scopeKey = buildScopeKey(agentId, scope);
    const normalizedName = runtimeTool.name.normalize('NFC');
    const canonicalRuntime = canonicalizeToolDefinition(runtimeTool);
    const runtimeHash = await sha256Hex(canonicalRuntime);

    const unicodeAnomalies = [
      ...detectUnicodeAnomalies(runtimeTool.name),
      ...detectUnicodeAnomalies(runtimeTool.description),
      ...detectUnicodeAnomalies(JSON.stringify(runtimeTool.inputSchema)),
    ];

    const scopeMap = this.baselines.get(scopeKey);
    const baseline = scopeMap?.get(normalizedName);

    if (!baseline) {
      this.quarantinedTools.add(`${scopeKey}::${normalizedName}`);
      return {
        allowed: false,
        status: 'UNREGISTERED_TOOL',
        scopeKey,
        toolName: normalizedName,
        baselineHash: null,
        runtimeHash,
        canonicalBaseline: null,
        canonicalRuntime,
        diffFields: ['name'],
        unicodeAnomalies,
        reason: `Tool "${normalizedName}" is missing from the (${agentId}, ${scope}) baseline registry. Out-of-process gateway rejected mounting and quarantined it.`,
      };
    }

    if (baseline.sha256 !== runtimeHash) {
      this.quarantinedTools.add(`${scopeKey}::${normalizedName}`);
      const baseObj = JSON.parse(baseline.canonicalJson) as Record<string, unknown>;
      const runObj = JSON.parse(canonicalRuntime) as Record<string, unknown>;
      const diffFields: Array<'name' | 'description' | 'inputSchema' | 'annotations'> = [];
      for (const field of ['name', 'description', 'inputSchema', 'annotations'] as const) {
        if (JSON.stringify(baseObj[field]) !== JSON.stringify(runObj[field])) {
          diffFields.push(field);
        }
      }
      return {
        allowed: false,
        status: 'QUARANTINED_HASH_DRIFT',
        scopeKey,
        toolName: normalizedName,
        baselineHash: baseline.sha256,
        runtimeHash,
        canonicalBaseline: baseline.canonicalJson,
        canonicalRuntime,
        diffFields,
        unicodeAnomalies,
        reason: `Runtime MCP definition hash drift detected (suspected Rug Pull). Affected fields: ${diffFields.join(', ')}. Execution blocked and tool quarantined outside model process.`,
      };
    }

    return {
      allowed: true,
      status: 'VERIFIED',
      scopeKey,
      toolName: normalizedName,
      baselineHash: baseline.sha256,
      runtimeHash,
      canonicalBaseline: baseline.canonicalJson,
      canonicalRuntime,
      diffFields: [],
      unicodeAnomalies,
      reason: `Tool "${normalizedName}" canonical SHA-256 matches the (${agentId}, ${scope}) baseline lock. Execution permitted.`,
    };
  }
}
