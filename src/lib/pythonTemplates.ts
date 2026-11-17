export interface PythonModuleSpec {
  id: 'mcp_lock' | 'itsm_verify' | 'forensics_ledger' | 'agent_loop';
  filename: string;
  title: string;
  subtitle: string;
  code: string;
}

export const PYTHON_MODULES: PythonModuleSpec[] = [
  {
    id: 'mcp_lock',
    filename: 'canonical_mcp_hash_lock.py',
    title: 'CanonicalMCPHashLock',
    subtitle: 'OWASP Agentic V2 & NHIMG MCP Rug Pull out-of-process canonical SHA-256 hash lock',
    code: `from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MCPToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HashLockVerdict:
    allowed: bool
    status: str  # "VERIFIED" | "QUARANTINED_HASH_DRIFT" | "UNREGISTERED_TOOL"
    scope_key: str
    tool_name: str
    baseline_hash: str | None
    runtime_hash: str
    diff_fields: tuple[str, ...]
    reason: str


def _canonicalize_value(value: Any) -> Any:
    """Recursively sort object keys and normalize strings to Unicode NFC to eliminate drift."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_canonicalize_value(item) for item in value]
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _canonicalize_value(v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            if v is not None
        }
    return value


def canonicalize_tool_definition(tool: MCPToolDefinition) -> str:
    payload = _canonicalize_value(
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
            "annotations": tool.annotations or {},
        }
    )
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def compute_tool_sha256(tool: MCPToolDefinition) -> tuple[str, str]:
    canonical = canonicalize_tool_definition(tool)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest, canonical


class CanonicalMCPHashLock:
    """Out-of-process MCP definition lock bound by (agent_id, scope) to block runtime Rug Pulls."""

    def __init__(self) -> None:
        self._baselines: dict[tuple[str, str], dict[str, tuple[str, str]]] = {}
        self._quarantined: set[tuple[str, str, str]] = set()

    def bind_baseline(
        self, agent_id: str, scope: str, tools: list[MCPToolDefinition]
    ) -> dict[str, str]:
        key = (unicodedata.normalize("NFC", agent_id), unicodedata.normalize("NFC", scope))
        registry: dict[str, tuple[str, str]] = {}
        hashes: dict[str, str] = {}
        for tool in tools:
            norm_name = unicodedata.normalize("NFC", tool.name)
            digest, canonical = compute_tool_sha256(tool)
            registry[norm_name] = (digest, canonical)
            hashes[norm_name] = digest
            self._quarantined.discard((key[0], key[1], norm_name))
        self._baselines[key] = registry
        return hashes

    def verify_and_gate(
        self, agent_id: str, scope: str, runtime_tool: MCPToolDefinition
    ) -> HashLockVerdict:
        key = (unicodedata.normalize("NFC", agent_id), unicodedata.normalize("NFC", scope))
        norm_name = unicodedata.normalize("NFC", runtime_tool.name)
        runtime_hash, canonical_runtime = compute_tool_sha256(runtime_tool)
        scope_key = f"{key[0]}::{key[1]}"

        registry = self._baselines.get(key, {})
        if norm_name not in registry:
            self._quarantined.add((key[0], key[1], norm_name))
            return HashLockVerdict(
                allowed=False,
                status="UNREGISTERED_TOOL",
                scope_key=scope_key,
                tool_name=norm_name,
                baseline_hash=None,
                runtime_hash=runtime_hash,
                diff_fields=("name",),
                reason=f"Tool '{norm_name}' is missing from ({key[0]}, {key[1]}) baseline.",
            )

        baseline_hash, canonical_baseline = registry[norm_name]
        if baseline_hash != runtime_hash:
            self._quarantined.add((key[0], key[1], norm_name))
            base_obj = json.loads(canonical_baseline)
            run_obj = json.loads(canonical_runtime)
            diff = tuple(
                f for f in ("name", "description", "inputSchema", "annotations")
                if base_obj.get(f) != run_obj.get(f)
            )
            return HashLockVerdict(
                allowed=False,
                status="QUARANTINED_HASH_DRIFT",
                scope_key=scope_key,
                tool_name=norm_name,
                baseline_hash=baseline_hash,
                runtime_hash=runtime_hash,
                diff_fields=diff,
                reason=f"MCP Rug Pull detected on '{norm_name}'. Quarantined outside model process.",
            )

        return HashLockVerdict(
            allowed=True,
            status="VERIFIED",
            scope_key=scope_key,
            tool_name=norm_name,
            baseline_hash=baseline_hash,
            runtime_hash=runtime_hash,
            diff_fields=(),
            reason="Baseline SHA-256 lock verified.",
        )
`,
  },
  {
    id: 'itsm_verify',
    filename: 'verify_soc_verdict_with_itsm.py',
    title: 'verify_soc_verdict_with_itsm',
    subtitle: 'Anti-Poisoning the Watchtower random nonce envelope & deterministic ITSM cross-verification',
    code: `from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

FORGED_TAG_RE = re.compile(r"</?\\s*untrusted_telemetry_[0-9a-f]*\\s*>", re.IGNORECASE)


@dataclass(frozen=True)
class ITSMChangeRecord:
    ticket_id: str
    hostname: str
    approved_window_start: datetime
    approved_window_end: datetime
    status: Literal["APPROVED", "IN_PROGRESS", "EXPIRED", "REJECTED"]


@dataclass(frozen=True)
class NonceEnvelope:
    nonce: str
    wrapped_log: str
    breakout_attempt_detected: bool


@dataclass(frozen=True)
class SocVerificationResult:
    final_verdict: str
    escalated: bool
    matched_ticket_id: str | None
    checks: dict[str, bool]
    reason: str


def wrap_untrusted_telemetry(raw_log: str) -> NonceEnvelope:
    """Generate a dynamic 16-hex nonce tag per investigation and strip forged envelope tags."""
    nonce = secrets.token_hex(8)  # 16 hex chars
    breakout_detected = bool(FORGED_TAG_RE.search(raw_log))
    sanitized = FORGED_TAG_RE.sub("[STRIPPED_FORGED_ENVELOPE_TAG]", raw_log)
    wrapped = f"<untrusted_telemetry_{nonce}>\\n{sanitized}\\n</untrusted_telemetry_{nonce}>"
    return NonceEnvelope(
        nonce=nonce,
        wrapped_log=wrapped,
        breakout_attempt_detected=breakout_detected,
    )


def verify_soc_verdict_with_itsm(
    model_verdict: Literal["BTP", "TP", "FP"],
    claimed_ticket_id: str | None,
    observed_hostname: str,
    event_timestamp: datetime,
    itsm_table: dict[str, ITSMChangeRecord],
    envelope: NonceEnvelope,
) -> SocVerificationResult:
    """Cross-verify any BTP verdict against ground-truth ITSM records outside the model process."""
    if model_verdict != "BTP":
        return SocVerificationResult(
            final_verdict="TP_CONFIRMED" if model_verdict == "TP" else "FP_CONFIRMED",
            escalated=(model_verdict == "TP"),
            matched_ticket_id=None,
            checks={"envelope_clean": not envelope.breakout_attempt_detected},
            reason="Non-BTP verdict retained without ITSM maintenance exemption.",
        )

    norm_ticket = (claimed_ticket_id or "").strip().upper()
    record = itsm_table.get(norm_ticket)

    checks = {
        "envelope_clean": not envelope.breakout_attempt_detected,
        "ticket_approved": record is not None and record.status in ("APPROVED", "IN_PROGRESS"),
        "hostname_match": record is not None and record.hostname.lower() == observed_hostname.strip().lower(),
        "within_approved_window": (
            record is not None
            and record.approved_window_start <= event_timestamp <= record.approved_window_end
        ),
    }

    if not all(checks.values()):
        return SocVerificationResult(
            final_verdict="TP_ESCALATED_LOG_INJECTION_SUSPECTED",
            escalated=True,
            matched_ticket_id=record.ticket_id if record else None,
            checks=checks,
            reason=(
                "BTP verdict failed deterministic ITSM cross-verification "
                "(ticket_id, hostname, approved_window, or envelope integrity). "
                "Escalated to TP_ESCALATED_LOG_INJECTION_SUSPECTED."
            ),
        )

    return SocVerificationResult(
        final_verdict="BTP_VERIFIED_WITH_ITSM",
        escalated=False,
        matched_ticket_id=record.ticket_id,
        checks=checks,
        reason=f"Verified BTP against approved ITSM change {record.ticket_id}.",
    )
`,
  },
  {
    id: 'forensics_ledger',
    filename: 'trajectory_forensics_ledger.py',
    title: 'TrajectoryForensicsLedger',
    subtitle: 'Chained SHA-256 forensics ledger satisfying Google DeepMind (#143922037276975814) & Snowflake (#ASHREQ-8175)',
    code: `from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class LedgerEntry:
    step_index: int
    timestamp_iso: str
    phase: str
    agent_id: str
    hypothesis: str
    tool_name: str
    tool_args: dict[str, Any]
    result_summary: str
    verdict: str
    compliance_ref: str
    prev_hash: str
    entry_hash: str


def _compute_step_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    canonical_json = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    material = f"{prev_hash}|{canonical_json}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class TrajectoryForensicsLedger:
    """Tamper-evident chained SHA-256 trajectory ledger for structured replay and forensics."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    @property
    def tip_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append_step(
        self,
        *,
        phase: str,
        agent_id: str,
        hypothesis: str,
        tool_name: str,
        tool_args: dict[str, Any],
        result_summary: str,
        verdict: str,
        compliance_ref: str = "DeepMind#143922037276975814;Snowflake#ASHREQ-8175",
    ) -> LedgerEntry:
        step_index = len(self._entries)
        timestamp_iso = datetime.now(timezone.utc).isoformat()
        prev_hash = self.tip_hash

        payload = {
            "step_index": step_index,
            "timestamp_iso": timestamp_iso,
            "phase": phase,
            "agent_id": agent_id,
            "hypothesis": hypothesis,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "result_summary": result_summary,
            "verdict": verdict,
            "compliance_ref": compliance_ref,
        }
        entry_hash = _compute_step_hash(prev_hash, payload)
        entry = LedgerEntry(**payload, prev_hash=prev_hash, entry_hash=entry_hash)
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> tuple[bool, int | None]:
        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.step_index != idx or entry.prev_hash != expected_prev:
                return False, idx
            payload = asdict(entry)
            payload.pop("prev_hash")
            payload.pop("entry_hash")
            if _compute_step_hash(expected_prev, payload) != entry.entry_hash:
                return False, idx
            expected_prev = entry.entry_hash
        return True, None

    def export_replay_json(self) -> str:
        return json.dumps([asdict(e) for e in self._entries], ensure_ascii=False, indent=2)
`,
  },
  {
    id: 'agent_loop',
    filename: 'agent_core_gateway_loop.py',
    title: 'AgenticGatewayV2 Loop',
    subtitle: 'Full Agent loop integrating Decisions API precheck + MCP hash lock + Nonce/ITSM verification + forensics ledger',
    code: `from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from canonical_mcp_hash_lock import CanonicalMCPHashLock, MCPToolDefinition
from trajectory_forensics_ledger import TrajectoryForensicsLedger
from verify_soc_verdict_with_itsm import (
    ITSMChangeRecord,
    verify_soc_verdict_with_itsm,
    wrap_untrusted_telemetry,
)


def run_deterministic_soc_turn(
    *,
    agent_id: str,
    scope: str,
    raw_log: str,
    observed_hostname: str,
    event_timestamp: datetime,
    runtime_tool: MCPToolDefinition,
    tool_args: dict[str, Any],
    hash_lock: CanonicalMCPHashLock,
    itsm_table: dict[str, ITSMChangeRecord],
    ledger: TrajectoryForensicsLedger,
    decisions_classifier: Callable[[str], str],
    model_triage: Callable[[str], tuple[str, str | None]],
) -> dict[str, Any]:
    """Out-of-process deterministic gateway preventing prompt injection or tool drift from breaching control."""

    # 1. Decisions API zero-output-cost closed-set precheck
    precheck_route = decisions_classifier(raw_log)
    ledger.append_step(
        phase="DECISIONS_PRECHECK",
        agent_id=agent_id,
        hypothesis="Closed-set classifier routes incoming telemetry payload",
        tool_name="decisions.create",
        tool_args={"taxonomy": ["CLOSE_BENIGN_MAINTENANCE", "ESCALATE_INCIDENT", "BLOCK_LOG_INJECTION"]},
        result_summary=f"route={precheck_route}",
        verdict=precheck_route,
    )

    # 2. Out-of-process MCP canonical SHA-256 hash lock before tool execution
    lock_verdict = hash_lock.verify_and_gate(agent_id, scope, runtime_tool)
    ledger.append_step(
        phase="MCP_HASH_LOCK",
        agent_id=agent_id,
        hypothesis=f"Verify MCP canonical baseline SHA-256 before executing {runtime_tool.name}",
        tool_name=runtime_tool.name,
        tool_args=tool_args,
        result_summary=lock_verdict.reason,
        verdict=lock_verdict.status,
    )
    if not lock_verdict.allowed:
        return {"status": "BLOCKED_BY_MCP_LOCK", "lock_verdict": lock_verdict, "ledger": ledger}

    # 3. Dynamic 16-hex random nonce envelope around untrusted telemetry
    envelope = wrap_untrusted_telemetry(raw_log)
    ledger.append_step(
        phase="NONCE_ENVELOPE",
        agent_id=agent_id,
        hypothesis="Isolate untrusted telemetry boundary using dynamic random nonce tag",
        tool_name="wrap_untrusted_telemetry",
        tool_args={"nonce": envelope.nonce},
        result_summary=f"breakout_detected={envelope.breakout_attempt_detected}",
        verdict="ENVELOPE_SEALED",
    )

    # 4. Invoke LLM triage, then deterministically cross-verify ITSM table outside model process
    model_verdict, claimed_ticket_id = model_triage(envelope.wrapped_log)
    itsm_result = verify_soc_verdict_with_itsm(
        model_verdict=model_verdict,  # type: ignore[arg-type]
        claimed_ticket_id=claimed_ticket_id,
        observed_hostname=observed_hostname,
        event_timestamp=event_timestamp,
        itsm_table=itsm_table,
        envelope=envelope,
    )
    ledger.append_step(
        phase="ITSM_VERIFICATION",
        agent_id=agent_id,
        hypothesis="Cross-verify BTP verdict against ITSM (ticket_id, hostname, approved_window)",
        tool_name="verify_soc_verdict_with_itsm",
        tool_args={"model_verdict": model_verdict, "claimed_ticket_id": claimed_ticket_id},
        result_summary=itsm_result.reason,
        verdict=itsm_result.final_verdict,
    )

    return {"status": "COMPLETED", "itsm_result": itsm_result, "ledger": ledger}
`,
  },
];
