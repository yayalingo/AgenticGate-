export interface ITSMChangeRecord {
  ticketId: string;
  hostname: string;
  approvedWindowStart: string;
  approvedWindowEnd: string;
  changeOwner: string;
  summary: string;
  status: 'APPROVED' | 'IN_PROGRESS' | 'EXPIRED' | 'REJECTED';
}

export interface WrappedTelemetry {
  nonce: string;
  openTag: string;
  closeTag: string;
  envelopeText: string;
  breakoutAttemptDetected: boolean;
}

export type ModelVerdict = 'BTP' | 'TP' | 'FP';

export type FinalSocVerdict =
  | 'BTP_VERIFIED_WITH_ITSM'
  | 'TP_ESCALATED_LOG_INJECTION_SUSPECTED'
  | 'TP_CONFIRMED'
  | 'FP_CONFIRMED';

export type DecisionsApiRoute =
  | 'CLOSE_BENIGN_MAINTENANCE'
  | 'ESCALATE_INCIDENT'
  | 'BLOCK_LOG_INJECTION';

export interface VerificationCheckItem {
  id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export interface SocVerificationInput {
  modelVerdict: ModelVerdict;
  claimedTicketId: string | null;
  observedHostname: string;
  eventTimestampIso: string;
  itsmTable: ITSMChangeRecord[];
  rawLog: string;
  nonce?: string;
}

export interface SocVerificationResult {
  finalVerdict: FinalSocVerdict;
  escalated: boolean;
  decisionsApiRoute: DecisionsApiRoute;
  decisionsLatencyMs: number;
  envelope: WrappedTelemetry;
  matchedTicket: ITSMChangeRecord | null;
  checks: VerificationCheckItem[];
  reason: string;
}

export function generateNonceHex(byteLength = 8): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function wrapUntrustedTelemetry(
  rawLog: string,
  providedNonce?: string
): WrappedTelemetry {
  const nonce = providedNonce && /^[0-9a-f]{8,32}$/i.test(providedNonce)
    ? providedNonce.toLowerCase()
    : generateNonceHex(8);
  const openTag = `<untrusted_telemetry_${nonce}>`;
  const closeTag = `</untrusted_telemetry_${nonce}>`;

  const breakoutPattern = /<\/?\s*untrusted_telemetry_[0-9a-f]*\s*>/gi;
  const breakoutAttemptDetected = breakoutPattern.test(rawLog);
  const sanitizedBody = rawLog.replace(
    breakoutPattern,
    '[STRIPPED_FORGED_ENVELOPE_TAG]'
  );

  return {
    nonce,
    openTag,
    closeTag,
    envelopeText: `${openTag}\n${sanitizedBody}\n${closeTag}`,
    breakoutAttemptDetected,
  };
}

export function extractTicketIdFromLog(rawLog: string): string | null {
  const match = rawLog.match(/\b(CHG-\d{4}-\d{3,6}|CHG-\d{3,8}|INC-\d{4}-\d{3,6})\b/i);
  return match ? match[1].toUpperCase() : null;
}

export function verifySocVerdictWithItsm(
  input: SocVerificationInput
): SocVerificationResult {
  const envelope = wrapUntrustedTelemetry(input.rawLog, input.nonce);
  const checks: VerificationCheckItem[] = [];

  checks.push({
    id: 'nonce_envelope',
    label: 'Random Nonce Envelope Integrity',
    passed: !envelope.breakoutAttemptDetected,
    detail: envelope.breakoutAttemptDetected
      ? 'Detected forged </untrusted_telemetry_*> escape tag in raw log; stripped and flagged high-risk injection signal'
      : `Isolated untrusted telemetry using dynamic 16-hex tag <untrusted_telemetry_${envelope.nonce}>`,
  });

  if (input.modelVerdict !== 'BTP') {
    const isTp = input.modelVerdict === 'TP';
    return {
      finalVerdict: isTp ? 'TP_CONFIRMED' : 'FP_CONFIRMED',
      escalated: isTp,
      decisionsApiRoute: isTp ? 'ESCALATE_INCIDENT' : 'CLOSE_BENIGN_MAINTENANCE',
      decisionsLatencyMs: 14,
      envelope,
      matchedTicket: null,
      checks,
      reason: isTp
        ? 'Model classified alert as True Positive (TP); maintaining high-priority incident escalation.'
        : 'Model classified alert as False Positive (FP); ITSM maintenance exemption path not invoked.',
    };
  }

  const normalizedTicketId = (input.claimedTicketId ?? '').trim().toUpperCase();
  const ticketRecord =
    input.itsmTable.find(
      (rec) => rec.ticketId.toUpperCase() === normalizedTicketId
    ) ?? null;

  const ticketExistsAndApproved =
    ticketRecord !== null &&
    (ticketRecord.status === 'APPROVED' || ticketRecord.status === 'IN_PROGRESS');

  checks.push({
    id: 'ticket_existence',
    label: 'ITSM Ticket Existence & Approval Status',
    passed: ticketExistsAndApproved,
    detail: !normalizedTicketId
      ? 'Model output BTP without providing a verifiable ITSM ticket_id'
      : !ticketRecord
      ? `Ticket ${normalizedTicketId} does not exist in the enterprise ITSM change table`
      : ticketExistsAndApproved
      ? `Ticket ${ticketRecord.ticketId} is active (${ticketRecord.status})`
      : `Ticket ${ticketRecord.ticketId} has status ${ticketRecord.status} and cannot authorize maintenance exemption`,
  });

  const hostMatches =
    ticketRecord !== null &&
    ticketRecord.hostname.toLowerCase() === input.observedHostname.trim().toLowerCase();

  checks.push({
    id: 'hostname_match',
    label: 'Target Hostname Exact Match',
    passed: hostMatches,
    detail: !ticketRecord
      ? 'Cannot verify hostname without a valid ITSM ticket'
      : hostMatches
      ? `Hostname verified (${ticketRecord.hostname})`
      : `Hostname mismatch: observed host is ${input.observedHostname}, ticket authorizes ${ticketRecord.hostname}`,
  });

  const eventMs = Date.parse(input.eventTimestampIso);
  const startMs = ticketRecord ? Date.parse(ticketRecord.approvedWindowStart) : NaN;
  const endMs = ticketRecord ? Date.parse(ticketRecord.approvedWindowEnd) : NaN;
  const windowMatches =
    ticketRecord !== null &&
    !Number.isNaN(eventMs) &&
    !Number.isNaN(startMs) &&
    !Number.isNaN(endMs) &&
    eventMs >= startMs &&
    eventMs <= endMs;

  checks.push({
    id: 'approved_window',
    label: 'Approved Maintenance Window Cross-Check',
    passed: windowMatches,
    detail: !ticketRecord
      ? 'Cannot verify maintenance window without a valid ITSM ticket'
      : windowMatches
      ? `Event timestamp ${input.eventTimestampIso} falls within [${ticketRecord.approvedWindowStart} ~ ${ticketRecord.approvedWindowEnd}]`
      : `Event timestamp ${input.eventTimestampIso} is outside approved window [${ticketRecord.approvedWindowStart} ~ ${ticketRecord.approvedWindowEnd}]`,
  });

  const allPassed = checks.every((c) => c.passed);

  if (!allPassed) {
    return {
      finalVerdict: 'TP_ESCALATED_LOG_INJECTION_SUSPECTED',
      escalated: true,
      decisionsApiRoute: 'BLOCK_LOG_INJECTION',
      decisionsLatencyMs: 11,
      envelope,
      matchedTicket: ticketRecord,
      checks,
      reason:
        'Model classified alert as BTP (benign maintenance), but out-of-process ITSM cross-verification failed. Escalated to TP_ESCALATED_LOG_INJECTION_SUSPECTED (suspected Poisoning the Watchtower attack).',
    };
  }

  return {
    finalVerdict: 'BTP_VERIFIED_WITH_ITSM',
    escalated: false,
    decisionsApiRoute: 'CLOSE_BENIGN_MAINTENANCE',
    decisionsLatencyMs: 9,
    envelope,
    matchedTicket: ticketRecord,
    checks,
    reason: `Out-of-process ITSM verification passed: ticket ${ticketRecord!.ticketId} covers host ${ticketRecord!.hostname} within the approved maintenance window.`,
  };
}
