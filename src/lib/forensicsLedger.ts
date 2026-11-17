import { canonicalizeValue, sha256Hex } from './canonicalMcpLock';

export const GENESIS_HASH = '0'.repeat(64);

export type TrajectoryPhase =
  | 'DECISIONS_PRECHECK'
  | 'MCP_HASH_LOCK'
  | 'NONCE_ENVELOPE'
  | 'ITSM_VERIFICATION'
  | 'AGENT_HYPOTHESIS';

export interface LedgerStepPayload {
  stepIndex: number;
  timestampIso: string;
  phase: TrajectoryPhase;
  agentId: string;
  hypothesis: string;
  toolName: string;
  toolArgs: Record<string, unknown>;
  resultSummary: string;
  verdict: string;
  complianceRef: string;
}

export interface LedgerEntry extends LedgerStepPayload {
  prevHash: string;
  entryHash: string;
}

export interface ChainVerificationReport {
  valid: boolean;
  totalSteps: number;
  brokenAtIndex: number | null;
  failureReason: string | null;
  stepResults: Array<{
    stepIndex: number;
    valid: boolean;
    expectedPrevHash: string;
    actualPrevHash: string;
    expectedEntryHash: string;
    actualEntryHash: string;
  }>;
}

export function buildCanonicalStepString(payload: LedgerStepPayload): string {
  return JSON.stringify(canonicalizeValue(payload));
}

export async function computeEntryHash(
  prevHash: string,
  payload: LedgerStepPayload
): Promise<string> {
  const canonicalPayload = buildCanonicalStepString(payload);
  return sha256Hex(`${prevHash}|${canonicalPayload}`);
}

export class TrajectoryForensicsLedger {
  private entries: LedgerEntry[] = [];

  constructor(initialEntries: LedgerEntry[] = []) {
    this.entries = initialEntries.map((e) => ({ ...e }));
  }

  getEntries(): LedgerEntry[] {
    return this.entries.map((e) => ({ ...e }));
  }

  getTipHash(): string {
    if (this.entries.length === 0) return GENESIS_HASH;
    return this.entries[this.entries.length - 1].entryHash;
  }

  async appendStep(
    input: Omit<LedgerStepPayload, 'stepIndex' | 'timestampIso'> & {
      timestampIso?: string;
    }
  ): Promise<LedgerEntry> {
    const stepIndex = this.entries.length;
    const prevHash = this.getTipHash();
    const payload: LedgerStepPayload = {
      stepIndex,
      timestampIso: input.timestampIso ?? new Date().toISOString(),
      phase: input.phase,
      agentId: input.agentId,
      hypothesis: input.hypothesis,
      toolName: input.toolName,
      toolArgs: input.toolArgs,
      resultSummary: input.resultSummary,
      verdict: input.verdict,
      complianceRef: input.complianceRef,
    };

    const entryHash = await computeEntryHash(prevHash, payload);
    const entry: LedgerEntry = {
      ...payload,
      prevHash,
      entryHash,
    };
    this.entries.push(entry);
    return entry;
  }

  static async verifyChain(entries: LedgerEntry[]): Promise<ChainVerificationReport> {
    const stepResults: ChainVerificationReport['stepResults'] = [];
    let expectedPrevHash = GENESIS_HASH;
    let brokenAtIndex: number | null = null;
    let failureReason: string | null = null;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const payload: LedgerStepPayload = {
        stepIndex: entry.stepIndex,
        timestampIso: entry.timestampIso,
        phase: entry.phase,
        agentId: entry.agentId,
        hypothesis: entry.hypothesis,
        toolName: entry.toolName,
        toolArgs: entry.toolArgs,
        resultSummary: entry.resultSummary,
        verdict: entry.verdict,
        complianceRef: entry.complianceRef,
      };
      const expectedEntryHash = await computeEntryHash(expectedPrevHash, payload);
      const prevMatches = entry.prevHash === expectedPrevHash;
      const hashMatches = entry.entryHash === expectedEntryHash;
      const indexMatches = entry.stepIndex === i;
      const stepValid = prevMatches && hashMatches && indexMatches;

      stepResults.push({
        stepIndex: i,
        valid: stepValid,
        expectedPrevHash,
        actualPrevHash: entry.prevHash,
        expectedEntryHash,
        actualEntryHash: entry.entryHash,
      });

      if (!stepValid && brokenAtIndex === null) {
        brokenAtIndex = i;
        if (!indexMatches) {
          failureReason = `Step #${i} index is non-contiguous (found ${entry.stepIndex}).`;
        } else if (!prevMatches) {
          failureReason = `Step #${i} prevHash does not match step #${i - 1} entryHash; hash chain broken.`;
        } else {
          failureReason = `Step #${i} payload digest does not match recorded entryHash; entry tampered post-commit.`;
        }
      }

      expectedPrevHash = entry.entryHash;
    }

    return {
      valid: brokenAtIndex === null,
      totalSteps: entries.length,
      brokenAtIndex,
      failureReason,
      stepResults,
    };
  }
}

export interface SocForensicExportBundle {
  schemaVersion: 'owasp.agentic.v2.soc-forensics/1.0';
  exportedAtIso: string;
  genesisHash: string;
  tipHash: string;
  ledgerEntries: LedgerEntry[];
  chainReport: ChainVerificationReport;
}

export async function buildSocForensicExportBundle(params: {
  ledgerEntries: LedgerEntry[];
  chainReport?: ChainVerificationReport | null;
  exportedAtIso?: string;
}): Promise<SocForensicExportBundle> {
  const ledgerEntries = params.ledgerEntries.map((entry) => ({ ...entry }));
  const resolvedReport =
    params.chainReport ??
    (await TrajectoryForensicsLedger.verifyChain(ledgerEntries));
  const tipHash =
    ledgerEntries.length > 0
      ? ledgerEntries[ledgerEntries.length - 1].entryHash
      : GENESIS_HASH;

  return {
    schemaVersion: 'owasp.agentic.v2.soc-forensics/1.0',
    exportedAtIso: params.exportedAtIso ?? new Date().toISOString(),
    genesisHash: GENESIS_HASH,
    tipHash,
    ledgerEntries,
    chainReport: resolvedReport,
  };
}

export function formatSocForensicExportJson(
  bundle: SocForensicExportBundle
): string {
  return JSON.stringify(bundle, null, 2);
}

