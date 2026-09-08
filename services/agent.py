"""
Agentic investigation.

Single-shot mode hands the model a package and gets a plan back. Agentic
mode lets the model ask questions first. It gets the same package plus a
set of read-only tools, and it can call them, look at the answers, and
call more before committing to a plan. This is Bedrock's native Converse
tool-use loop; no MCP server, no external runtime.

Guardrails, because "agent" without them is just "unbounded":

  - Every tool is read-only. Most operate on data already collected.
    The two that touch AWS (permission lookup, targeted event query) use
    the same assumed-role credentials and the same read-only APIs as the
    rest of the pipeline.
  - Hard cap on iterations. Default 8. The model gets told what the cap
    is and how many it has left.
  - Every tool call and result is recorded in an agent trace that lands
    in the evidence bundle. An analyst can replay exactly what the model
    asked and what it was told.
  - The terminal action is submit_investigation_plan. The loop ends when
    the model calls it, or when the cap is hit, in which case the model
    is forced to submit with what it has.
  - Containment stays out of reach. There is no tool for it.

The re-scoring hook from Phase 02 is exposed as a tool (resolve_blind_spot),
which is the Phase 03 seam pulled forward: the model can mark a gap as
closed based on evidence it found, and the plan reprioritizes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger(__name__)

DEFAULT_MAX_STEPS = 8


@dataclass
class ToolCall:
    step: int
    tool: str
    args: dict
    result_summary: str
    result_bytes: int
    at: str


@dataclass
class AgentTrace:
    """Audit record of an agentic run. Goes in the evidence bundle."""

    started_at: str
    max_steps: int
    calls: List[ToolCall] = field(default_factory=list)
    hit_cap: bool = False
    forced_submit: bool = False
    finished_at: Optional[str] = None
    total_input_tokens: int = 0
    total_output_tokens: int = 0

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "max_steps": self.max_steps,
            "steps_used": len(self.calls),
            "hit_cap": self.hit_cap,
            "forced_submit": self.forced_submit,
            "tokens": {"input": self.total_input_tokens, "output": self.total_output_tokens},
            "calls": [c.__dict__ for c in self.calls],
        }


# ----------------------------------------------------------------------
# Tool definitions. These are what the model sees.
# ----------------------------------------------------------------------

def build_tool_config(plan_schema: dict) -> dict:
    tools = [
        {"toolSpec": {
            "name": "get_actor_timeline",
            "description": "Full chronological timeline for one principal across all accounts "
                           "and regions in the collected evidence. Use when you need to see "
                           "everything an actor did, not just the sample.",
            "inputSchema": {"json": {"type": "object", "properties": {
                "actor": {"type": "string", "description": "Principal ARN or username as it appears in the evidence"}},
                "required": ["actor"]}}}},
        {"toolSpec": {
            "name": "get_session_detail",
            "description": "Every action taken under one assumed-role session. Use to see what "
                           "was done after a role pivot.",
            "inputSchema": {"json": {"type": "object", "properties": {
                "session_key": {"type": "string", "description": "Session key prefix as shown in session_chains"}},
                "required": ["session_key"]}}}},
        {"toolSpec": {
            "name": "query_events",
            "description": "Filter the collected evidence by event name, actor, and/or time range. "
                           "Returns up to 50 matching events.",
            "inputSchema": {"json": {"type": "object", "properties": {
                "event_names": {"type": "array", "items": {"type": "string"}},
                "actor_contains": {"type": "string"},
                "after": {"type": "string", "description": "ISO timestamp"},
                "before": {"type": "string", "description": "ISO timestamp"}}}}}},
        {"toolSpec": {
            "name": "check_principal_permissions",
            "description": "List the IAM policies attached to a user or role. Read-only. Use to "
                           "assess blast radius: what could this principal actually do?",
            "inputSchema": {"json": {"type": "object", "properties": {
                "principal_arn": {"type": "string"}},
                "required": ["principal_arn"]}}}},
        {"toolSpec": {
            "name": "lookup_indicator",
            "description": "Enrich one IP, domain, or hash against the configured threat feeds.",
            "inputSchema": {"json": {"type": "object", "properties": {
                "indicator": {"type": "string"}},
                "required": ["indicator"]}}}},
        {"toolSpec": {
            "name": "resolve_blind_spot",
            "description": "Mark an evidence gap as resolved because you found what was missing. "
                           "This re-scores affected steps. Only call this when evidence from a "
                           "prior tool call actually closes the gap.",
            "inputSchema": {"json": {"type": "object", "properties": {
                "blind_spot": {"type": "string", "description": "Text of the blind spot being resolved"},
                "evidence": {"type": "string", "description": "What you found that resolves it"}},
                "required": ["blind_spot", "evidence"]}}}},
        {"toolSpec": {
            "name": "submit_investigation_plan",
            "description": "Submit the final sequenced plan. This ends the investigation. "
                           "Call it once you have enough to sequence confidently.",
            "inputSchema": {"json": plan_schema}}},
    ]
    return {"tools": tools}


AGENT_SYSTEM_SUFFIX = """

You are running in agentic mode. Before submitting, you may call read-only
tools to look closer at anything in the package. Good reasons to call a tool:
an actor appears in an escalation chain and you want their full timeline;
a session chain has notable actions and you want to see all of them; a
persistence finding names a principal and you want to know what it can do.

You have a hard cap of {max_steps} tool calls. Spend them on what changes
the plan. When you have enough, call submit_investigation_plan. If you hit
the cap you will be asked to submit with what you have.

Every tool call is recorded and will be reviewed by the analyst."""


class InvestigationAgent:
    """Runs the Converse tool-use loop with guardrails."""

    def __init__(self, client, model_id: str, system_prompt: str, plan_schema: dict,
                 max_steps: int = DEFAULT_MAX_STEPS):
        self.client = client
        self.model_id = model_id
        self.system_prompt = system_prompt + AGENT_SYSTEM_SUFFIX.format(max_steps=max_steps)
        self.tool_config = build_tool_config(plan_schema)
        self.max_steps = max_steps
        self.handlers: Dict[str, Callable[[dict], Any]] = {}
        self.trace = AgentTrace(started_at=_now(), max_steps=max_steps)

    def register(self, name: str, fn: Callable[[dict], Any]) -> None:
        self.handlers[name] = fn

    def run(self, package: dict) -> dict:
        messages = [{"role": "user", "content": [{"text": json.dumps(package, indent=2, default=str)}]}]
        step = 0

        while True:
            resp = self.client.converse(
                modelId=self.model_id,
                system=[{"text": self.system_prompt}],
                messages=messages,
                toolConfig=self.tool_config,
                inferenceConfig={"temperature": 0.2, "maxTokens": 8192},
            )
            usage = resp.get("usage", {})
            self.trace.total_input_tokens += usage.get("inputTokens", 0)
            self.trace.total_output_tokens += usage.get("outputTokens", 0)

            content = resp["output"]["message"]["content"]
            messages.append({"role": "assistant", "content": content})

            tool_uses = [b["toolUse"] for b in content if "toolUse" in b]
            if not tool_uses:
                # model replied with text and no tool. Push it to submit.
                messages.append({"role": "user", "content": [
                    {"text": "Call submit_investigation_plan with your plan now."}]})
                step += 1
                if step > self.max_steps + 2:
                    raise RuntimeError("Agent did not submit a plan")
                continue

            # terminal?
            for tu in tool_uses:
                if tu["name"] == "submit_investigation_plan":
                    self.trace.finished_at = _now()
                    log.info("agent submitted after %d tool call(s)", len(self.trace.calls))
                    return tu["input"]

            # cap check before executing
            if step >= self.max_steps:
                self.trace.hit_cap = True
                self.trace.forced_submit = True
                messages.append({"role": "user", "content": [
                    {"toolResult": {"toolUseId": tu["toolUseId"],
                                    "content": [{"text": "Tool call budget exhausted."}],
                                    "status": "error"}} for tu in tool_uses
                ] + [{"text": "You have used all tool calls. Submit your plan now with "
                              "submit_investigation_plan."}]})
                step += 1
                continue

            # execute tools
            results = []
            for tu in tool_uses:
                step += 1
                name, args = tu["name"], tu.get("input", {}) or {}
                handler = self.handlers.get(name)
                if handler is None:
                    out = {"error": f"unknown tool {name}"}
                else:
                    try:
                        out = handler(args)
                    except Exception as exc:  # noqa: BLE001
                        out = {"error": str(exc)[:300]}
                payload = json.dumps(out, default=str)
                self.trace.calls.append(ToolCall(
                    step=step, tool=name, args=args,
                    result_summary=_summarize(out), result_bytes=len(payload), at=_now(),
                ))
                log.info("agent step %d/%d: %s(%s)", step, self.max_steps, name,
                         json.dumps(args)[:80])
                results.append({"toolResult": {
                    "toolUseId": tu["toolUseId"],
                    "content": [{"text": payload[:12_000]}],  # keep each result bounded
                }})
            remaining = max(0, self.max_steps - step)
            results.append({"text": f"{remaining} tool call(s) remaining."})
            messages.append({"role": "user", "content": results})


# ----------------------------------------------------------------------
# Default handlers. Operate on collected data; two touch AWS read-only.
# ----------------------------------------------------------------------

def make_handlers(events: List[dict], correlation: dict, intel_service, scorer,
                  broker=None, targets=None, plan_steps: Optional[List[dict]] = None,
                  pseudonymizer=None) -> Dict[str, Callable]:
    """Build the handler map. Everything closes over already-collected data.

    If a pseudonymizer is active, tool args arrive tokenized and results
    must be tokenized before returning. The restore/redact calls here
    handle that so the model never sees a real identifier through a tool.
    """
    def _r(x):  # restore incoming token -> real
        return pseudonymizer.restore(x) if pseudonymizer else x

    def _d(x):  # redact outgoing real -> token
        return pseudonymizer.redact(x) if pseudonymizer else x

    def get_actor_timeline(args):
        actor = _r(args.get("actor", ""))
        hits = [e for e in events if actor and actor in (_actor(e) or "")]
        hits.sort(key=lambda e: e.get("eventTime", ""))
        return _d({"actor": actor, "event_count": len(hits),
                   "events": [_brief(e) for e in hits[:60]]})

    def get_session_detail(args):
        key = args.get("session_key", "")
        for chain in correlation.get("session_chains", []):
            if chain.get("session_key", "").startswith(key[:8]):
                return _d(chain)
        return {"error": "session not found"}

    def query_events(args):
        names = set(args.get("event_names") or [])
        actor_sub = _r(args.get("actor_contains") or "")
        after, before = args.get("after"), args.get("before")
        out = []
        for e in events:
            if names and e.get("eventName") not in names:
                continue
            if actor_sub and actor_sub not in (_actor(e) or ""):
                continue
            t = e.get("eventTime", "")
            if after and t < after:
                continue
            if before and t > before:
                continue
            out.append(_brief(e))
            if len(out) >= 50:
                break
        return _d({"matched": len(out), "events": out})

    def check_principal_permissions(args):
        arn = _r(args.get("principal_arn", ""))
        if not broker or not targets:
            return {"error": "no AWS access in this mode"}
        acct = arn.split(":")[4] if arn.count(":") >= 5 else None
        target = next((t for t in targets if t.account_id == acct), None)
        if not target:
            return {"error": "principal's account not in scope"}
        iam_region = "us-gov-west-1" if broker.partition == "aws-us-gov" else "us-east-1"
        iam = broker.session_for(target, region=iam_region).client("iam")
        try:
            if ":user/" in arn:
                name = arn.split(":user/")[-1]
                attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
                inline = iam.list_user_policies(UserName=name).get("PolicyNames", [])
                groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=name).get("Groups", [])]
                return _d({"kind": "user", "name": name,
                           "attached": [p["PolicyName"] for p in attached],
                           "inline": inline, "groups": groups})
            if ":role/" in arn or ":assumed-role/" in arn:
                name = arn.split("/")[1] if ":assumed-role/" in arn else arn.split(":role/")[-1]
                attached = iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
                inline = iam.list_role_policies(RoleName=name).get("PolicyNames", [])
                return _d({"kind": "role", "name": name,
                           "attached": [p["PolicyName"] for p in attached], "inline": inline})
        except Exception as exc:  # noqa: BLE001
            return {"error": f"IAM lookup failed: {str(exc)[:200]}"}
        return {"error": "unrecognized principal shape"}

    def lookup_indicator(args):
        ind = _r(args.get("indicator", ""))
        from .threat_intel import IOC, IOCExtractor
        kind = "ip" if IOCExtractor._is_routable_ip(ind) else ("sha256" if len(ind) == 64 else "domain")
        enr = intel_service.enrich([IOC(ind, kind, "agent")])
        if not enr:
            return _d({"indicator": ind, "matched": False})
        e = next(iter(enr.values()))
        return _d({"indicator": ind, "matched": True, "confidence": e.confidence,
                   "groups": e.threat_group_names, "categories": e.categories})

    def resolve_blind_spot(args):
        spot = args.get("blind_spot", "")
        if not plan_steps:
            return {"resolved": spot, "note": "no plan steps loaded yet; will apply at scoring"}
        scorer.rescore_with_new_evidence(plan_steps, [spot])
        return {"resolved": spot, "rescored_steps": len(plan_steps)}

    return {
        "get_actor_timeline": get_actor_timeline,
        "get_session_detail": get_session_detail,
        "query_events": query_events,
        "check_principal_permissions": check_principal_permissions,
        "lookup_indicator": lookup_indicator,
        "resolve_blind_spot": resolve_blind_spot,
    }


def _actor(e: dict) -> str:
    a = e.get("actor")
    if isinstance(a, dict):
        return a.get("arn") or a.get("userName") or ""
    return ""


def _brief(e: dict) -> dict:
    return {"time": e.get("eventTime"), "event": e.get("eventName"),
            "actor": _actor(e), "ip": e.get("sourceIPAddress"),
            "account": e.get("account"), "region": e.get("awsRegion"),
            "error": e.get("errorCode"), "mfa": e.get("mfaAuthenticated")}


def _summarize(out: Any) -> str:
    if isinstance(out, dict):
        if "error" in out:
            return f"error: {out['error'][:80]}"
        keys = ", ".join(f"{k}={v}" for k, v in out.items()
                         if isinstance(v, (int, str, bool)) and k != "events")
        return keys[:160]
    return str(out)[:160]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
