"""
SPECTER — Systematic Priority Engine for Cloud Threat Evidence Reconstruction

Phase 02 orchestrator. Wires the full pipeline:

    accounts -> landscape -> collection -> correlation -> enrichment
             -> model -> scoring -> prioritized plan

Everything before the model call is deterministic and cheap. The model
sees a curated, correlated, enriched summary rather than raw logs, which
is what makes this viable against real estate volume.

Usage:
    python specter.py --accounts 111122223333,444455556666 --regions us-east-1
    python specter.py --discover --window-hours 48
    python specter.py --offline --evidence-dir synthetic_data
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from services.account_broker import AccountBroker, AccountTarget
from services.correlation_engine import CorrelationEngine
from services.evidence_collector import EvidenceCollector, EvidenceBundle
from services.landscape_mapper import LandscapeMapper, summarize_estate
from services.narrative_generator import NarrativeGenerator
from services.persistence_hunter import PersistenceHunter, summarize as summarize_persistence
from services.preservation import EvidencePreserver, ContainmentAdvisor
from services.timeline_export import TimelineExporter
from services.redaction import Pseudonymizer
from services.agent import InvestigationAgent, make_handlers
from services.scoring_engine import ScoringEngine
from services.threat_intel import ThreatIntelService

log = logging.getLogger("specter")

# Overridable via --model / --bedrock-region or SPECTER_MODEL_ID / SPECTER_BEDROCK_REGION.
# Defaults target GovCloud; commercial users typically want us-east-1.
import os
MODEL_ID = os.environ.get("SPECTER_MODEL_ID", "anthropic.claude-sonnet-4-5-20250929-v1:0")
AWS_REGION = os.environ.get("SPECTER_BEDROCK_REGION", "us-gov-west-1")

SYSTEM_PROMPT = """You are SPECTER, an investigation planner for cloud forensics analysts.

You receive a pre-correlated evidence package from one or more AWS accounts:
an evidence-landscape assessment, a filtered event timeline, correlation
findings, and threat intelligence enrichment.

Produce a sequenced investigation plan. For each step:
- Map to a MITRE ATT&CK for Cloud technique ID and tactic where one applies.
  Where the AWS Threat Technique Catalog (TTC) has an AWS-specific
  sub-technique, prefer it; the TTC reflects real AWS CIRT casework.
- State why it matters, referencing the specific evidence that motivates it.
- Note which sources support it and which are missing.
- Estimate response effort 1-5 (1 = minutes, 5 = major coordinated effort).
- Assess business criticality of the affected asset.

Rules that matter:
- Sequence by investigative value, not by chronology.
- Treat logging gaps as findings. Absent evidence during a gap is not
  evidence of absence; say so explicitly and plan around it.
- Where GuardDuty attack sequences are present, treat them as authoritative
  multi-stage correlation and build on them rather than re-deriving.
- Where the landscape shows a source was never enabled, do not plan steps
  that depend on it. Recommend enabling it instead.
- Persistence findings and attack patterns are already detected. Reference
  them by mechanism; plan verification and remediation around them.
- Session chains show what was done under each assumed role. Attribute
  actions to the originating principal, not just the role.
- Be explicit about confidence. Distinguish what evidence shows from what
  it suggests.

Use the submit_investigation_plan tool. Do not respond in plain text."""

PLAN_SCHEMA = {
                "type": "object",
                "properties": {
                    "environment_summary": {"type": "string"},
                    "forensic_readiness_notes": {"type": "string"},
                    "key_hypotheses": {"type": "array", "items": {"type": "string"}},
                    "confidence_statement": {"type": "string"},
                    "investigation_plan": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "step": {"type": "integer"},
                                "action": {"type": "string"},
                                "rationale": {"type": "string"},
                                "attack_technique_id": {"type": "string"},
                                "attack_technique_name": {"type": "string"},
                                "ttc_technique_id": {"type": "string",
                                    "description": "AWS Threat Technique Catalog ID if an AWS-specific sub-technique applies"},
                                "mitre_tactic": {"type": "string"},
                                "evidence_sources": {"type": "array", "items": {"type": "string"}},
                                "affected_accounts": {"type": "array", "items": {"type": "string"}},
                                "response_effort": {"type": "integer"},
                                "business_criticality": {
                                    "type": "object",
                                    "properties": {
                                        "asset_class": {"type": "string"},
                                        "criticality_tier": {"type": "integer"},
                                        "data_sensitivity": {"type": "string"},
                                        "impact_if_compromised": {"type": "string"},
                                        "sla_breach_risk": {"type": "boolean"},
                                    },
                                },
                                "threat_intel_enrichment": {
                                    "type": "object",
                                    "properties": {
                                        "linked_iocs": {"type": "array", "items": {"type": "string"}},
                                        "associated_threat_groups": {"type": "array", "items": {"type": "string"}},
                                        "confidence": {"type": "integer"},
                                        "data_sources": {"type": "array", "items": {"type": "string"}},
                                    },
                                },
                                "evidence_quality": {
                                    "type": "object",
                                    "properties": {
                                        "completeness": {"type": "integer"},
                                        "reliability": {"type": "integer"},
                                        "confidence": {"type": "integer"},
                                        "blind_spots": {"type": "array", "items": {"type": "string"}},
                                    },
                                },
                                "time_sensitivity": {
                                    "type": "object",
                                    "properties": {
                                        "incident_age_hours": {"type": "number"},
                                        "optimal_response_window_hours": {"type": "number"},
                                    },
                                },
                            },
                            "required": ["step", "action", "rationale"],
                        },
                    },
                },
                "required": ["investigation_plan", "key_hypotheses"],
            }

TOOL_CONFIG = {
    "tools": [{"toolSpec": {
        "name": "submit_investigation_plan",
        "description": "Submit the sequenced cloud forensics investigation plan.",
        "inputSchema": {"json": PLAN_SCHEMA},
    }}],
    "toolChoice": {"tool": {"name": "submit_investigation_plan"}},
}


class Specter:
    """End-to-end orchestrator."""

    def __init__(
        self,
        partition: str = "aws",
        business_context: str = "business_context.yaml",
        feed_dir: str = "mock_feeds",
        max_workers: int = 12,
        athena_config=None,
        model_id: Optional[str] = None,
        bedrock_region: Optional[str] = None,
        bedrock_endpoint: Optional[str] = None,
        redact: bool = False,
        agent_mode: bool = False,
        max_agent_steps: int = 8,
    ):
        self.model_id = model_id or MODEL_ID
        self.bedrock_region = bedrock_region or AWS_REGION
        self.bedrock_endpoint = bedrock_endpoint  # PrivateLink URL if set
        self.redact = redact
        self.agent_mode = agent_mode
        self.max_agent_steps = max_agent_steps
        self._targets = None
        self._bundle = None
        self.broker = AccountBroker(partition=partition)
        self.mapper = LandscapeMapper(self.broker, max_workers=max_workers)
        self.collector = EvidenceCollector(
            self.broker, max_workers=max_workers, athena_config=athena_config
        )
        self.correlator = CorrelationEngine()
        self.intel = ThreatIntelService(feed_dir=feed_dir)
        self.scorer = ScoringEngine(business_context)
        self.narrator = NarrativeGenerator()
        self.hunter = PersistenceHunter(self.broker, max_workers=max_workers)
        self.preserver = EvidencePreserver()
        self.advisor = ContainmentAdvisor()
        self.timeline = TimelineExporter()

    # ------------------------------------------------------------------

    def run(
        self,
        targets: List[AccountTarget],
        regions: List[str],
        window_hours: int = 72,
        token_budget: int = 40_000,
        skip_model: bool = False,
        hunt_live_state: bool = True,
        preserve: bool = True,
        case_id: Optional[str] = None,
    ) -> dict:
        started = datetime.now(timezone.utc)

        log.info("Phase 1/5: mapping evidence landscape")
        estate = self.mapper.map_estate(targets, regions)
        landscape_summary = summarize_estate(estate)

        self._targets = targets
        log.info("Phase 2/5: collecting and filtering evidence")
        bundle = self.collector.collect(
            targets, regions, window_hours=window_hours, token_budget=token_budget
        )

        self._bundle = bundle
        log.info("Phase 3/5: correlating across sources")
        correlation = self.correlator.correlate(
            bundle.events, bundle.findings, bundle.attack_sequences
        )

        log.info("Phase 4/7: enriching indicators")
        enrichment = self.intel.analyze(bundle.events, bundle.findings)

        log.info("Phase 5/7: hunting persistence")
        suspicious = {c.get("actor", "") for c in correlation.get("escalation_chains", [])}
        pfindings = self.hunter.hunt_events(bundle.events, suspicious)
        if hunt_live_state:
            pfindings += self.hunter.hunt_state(targets, regions)
        persistence = summarize_persistence(pfindings)

        preserved = None
        if preserve:
            log.info("Phase 6/7: preserving evidence")
            preserved = self.preserver.preserve(bundle, correlation, enrichment,
                                                landscape_summary, case_id=case_id)

        package = self._build_package(landscape_summary, bundle, correlation,
                                      enrichment, persistence)
        playbook = self.advisor.build_playbook(correlation, persistence)

        if skip_model:
            return {"evidence_package": package, "persistence": persistence,
                    "containment_playbook": playbook, "preserved": preserved,
                    "plan": None, "note": "Model invocation skipped (--dry-run)"}

        log.info("Phase 7/7: generating investigation plan%s",
                 " (agentic)" if self.agent_mode else "")
        plan = self._invoke_model(package, correlation, enrichment)
        # agent trace is produced by the model phase; append it to the bundle
        if preserved and getattr(self, "_agent_trace", None):
            import hashlib
            p = Path(preserved["path"]) / "agent_trace.json"
            raw = json.dumps(self._agent_trace, indent=2, sort_keys=True, default=str).encode()
            p.write_bytes(raw)
            preserved["agent_trace_sha256"] = hashlib.sha256(raw).hexdigest()

        steps = plan.get("investigation_plan", [])
        plan["investigation_plan"] = self.scorer.score_steps(steps)
        plan["critical_path"] = [
            s.get("step") for s in self.scorer.critical_path(steps)
        ]

        result = {
            "generated_at": started.isoformat(),
            "duration_seconds": round(
                (datetime.now(timezone.utc) - started).total_seconds(), 1
            ),
            "evidence_package": package,
            "persistence": persistence,
            "containment_playbook": playbook,
            "preserved": preserved,
            "plan": plan,
            "agent_trace": getattr(self, "_agent_trace", None),
            "model_config": {
                "model_id": self.model_id,
                "region": self.bedrock_region,
                "private_endpoint": bool(self.bedrock_endpoint),
                "redacted": self.redact,
                "agentic": self.agent_mode,
            },
        }
        result["incident_report"] = self.narrator.generate_report(result)
        result["executive_brief"] = self.narrator.executive_brief(result)
        return result

    # ------------------------------------------------------------------

    @staticmethod
    def _build_package(landscape, bundle: EvidenceBundle, correlation, enrichment,
                       persistence=None) -> dict:
        """Assemble what the model actually sees.

        On purpose, excludes raw logs. The model reasons over correlation
        output and a bounded event sample, never the full capture.
        """
        return {
            "evidence_landscape": landscape,
            "collection_stats": bundle.stats.to_dict(),
            "collection_window": {
                "start": bundle.window_start.isoformat() if bundle.window_start else None,
                "end": bundle.window_end.isoformat() if bundle.window_end else None,
            },
            "correlation": correlation,
            "threat_intelligence": enrichment,
            "persistence": persistence or {},
            "event_sample": bundle.events,
            "guardduty_findings": [
                {
                    "type": f.get("Type"),
                    "severity": f.get("Severity"),
                    "title": f.get("Title"),
                    "account": f.get("_specter_account"),
                    "region": f.get("_specter_region"),
                }
                for f in bundle.findings
            ],
        }

    def _bedrock_client(self):
        import boto3
        from botocore.config import Config as BotoConfig
        kwargs = dict(
            region_name=self.bedrock_region,
            config=BotoConfig(retries={"max_attempts": 5, "mode": "adaptive"},
                              read_timeout=180),
        )
        # PrivateLink: traffic never touches the regional public endpoint
        if self.bedrock_endpoint:
            kwargs["endpoint_url"] = self.bedrock_endpoint
        return boto3.client("bedrock-runtime", **kwargs)

    def _invoke_model(self, package: dict, correlation: dict = None,
                      enrichment: dict = None) -> dict:
        """Single-shot or agentic, with optional pseudonymization.

        Data path, in order:
          1. package is built from collected + correlated evidence
          2. if --redact, identifiers are tokenized (mapping stays in memory)
          3. the tokenized package goes to Bedrock in the configured region,
             via PrivateLink if --bedrock-endpoint is set
          4. the response is de-tokenized before anything else sees it
        Bedrock does not log or retain prompts/completions and does not use
        them for training. With --redact, it never sees a real identifier
        either.
        """
        try:
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            raise RuntimeError("boto3 required for model invocation; install it or use --dry-run")

        pseud = Pseudonymizer() if self.redact else None
        sendable = pseud.redact(package) if pseud else package
        if pseud:
            log.info("redaction: %d identifiers tokenized (%s)",
                     pseud.mapping_size,
                     ", ".join(f"{k}:{v}" for k, v in pseud.mapping_summary().items()))

        client = self._bedrock_client()
        self._agent_trace = None

        try:
            if self.agent_mode:
                plan = self._run_agent(client, sendable, correlation or {},
                                       enrichment or {}, pseud)
            else:
                plan = self._single_shot(client, sendable)
        except NoCredentialsError:
            raise RuntimeError("No AWS credentials configured")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            raise RuntimeError(
                f"Bedrock call failed ({code}). Verify model access for {self.model_id} "
                f"in {self.bedrock_region} with: aws bedrock list-foundation-models "
                f"--by-provider anthropic --region {self.bedrock_region}"
            ) from exc

        return pseud.restore(plan) if pseud else plan

    def _single_shot(self, client, sendable: dict) -> dict:
        import time
        from botocore.exceptions import ClientError
        message = json.dumps(sendable, indent=2, default=str)
        last_exc = None
        for attempt in range(3):
            try:
                response = client.converse(
                    modelId=self.model_id,
                    system=[{"text": SYSTEM_PROMPT}],
                    messages=[{"role": "user", "content": [{"text": message}]}],
                    toolConfig=TOOL_CONFIG,
                    inferenceConfig={"temperature": 0.2, "maxTokens": 8192},
                )
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("ThrottlingException", "ServiceUnavailableException") and attempt < 2:
                    wait = 2 ** (attempt + 1)
                    log.warning("Bedrock %s; retrying in %ds", code, wait)
                    time.sleep(wait)
                    last_exc = exc
                    continue
                raise
        else:
            raise RuntimeError("Bedrock throttled after 3 attempts") from last_exc

        for block in response["output"]["message"]["content"]:
            if "toolUse" in block:
                return block["toolUse"]["input"]
        raise RuntimeError("Model returned no tool call")

    def _run_agent(self, client, sendable: dict, correlation: dict,
                   enrichment: dict, pseud) -> dict:
        agent = InvestigationAgent(client, self.model_id, SYSTEM_PROMPT, PLAN_SCHEMA,
                                   max_steps=self.max_agent_steps)
        events = self._bundle.events if self._bundle else []
        handlers = make_handlers(events, correlation, self.intel, self.scorer,
                                 broker=self.broker, targets=self._targets,
                                 pseudonymizer=pseud)
        for name, fn in handlers.items():
            agent.register(name, fn)
        plan = agent.run(sendable)
        self._agent_trace = agent.trace.to_dict()
        return plan


# ----------------------------------------------------------------------


def render(result: dict) -> None:
    """Human-readable console output."""
    pkg = result.get("evidence_package", {})
    stats = pkg.get("collection_stats", {})
    landscape = pkg.get("evidence_landscape", {})
    corr = pkg.get("correlation", {}).get("summary", {})

    print("\n" + "=" * 74)
    print("SPECTER INVESTIGATION PLAN")
    print("=" * 74)

    print("\n-- EVIDENCE LANDSCAPE " + "-" * 52)
    print(f"  Accounts examined:        {landscape.get('accounts_examined', 0)}")
    print(f"  Account/regions reachable:{landscape.get('account_regions_reachable', 0)}"
          f" of {landscape.get('account_regions_examined', 0)}")
    print(f"  Mean readiness score:     {landscape.get('mean_readiness_score', 0)}/100")
    blind = landscape.get("regions_without_active_cloudtrail", [])
    if blind:
        print(f"  NO ACTIVE CLOUDTRAIL:     {', '.join(blind[:5])}"
              + (f" (+{len(blind) - 5} more)" if len(blind) > 5 else ""))

    print("\n-- COLLECTION " + "-" * 60)
    print(f"  Raw events:               {stats.get('raw_events', 0):,}")
    print(f"  After filtering:          {stats.get('after_dedup', 0):,}")
    print(f"  Sent to model:            {stats.get('selected', 0):,}")
    print(f"  Volume reduction:         {stats.get('reduction_ratio', 0) * 100:.1f}%")
    if stats.get("dropped_by_budget"):
        print(f"  Dropped by token budget:  {stats['dropped_by_budget']:,}")
    if stats.get("accounts_failed"):
        print(f"  Accounts unreachable:     {stats['accounts_failed']}")

    print("\n-- CORRELATION " + "-" * 59)
    print(f"  Distinct actors:          {corr.get('distinct_actors', 0)}")
    print(f"  Cross-account actors:     {corr.get('cross_account_actors', 0)}")
    print(f"  Logging gaps detected:    {corr.get('logging_gaps_detected', 0)}"
          f" ({corr.get('open_logging_gaps', 0)} still open)")
    print(f"  Escalation chains:        {corr.get('escalation_chains', 0)}")

    print(f"  Session chains:           {corr.get('session_chains', 0)}")
    print(f"  Attack patterns:          {corr.get('attack_patterns', 0)}")

    intel = pkg.get("threat_intelligence", {})
    if intel.get("attributed_groups"):
        print(f"  Attributed groups:        {', '.join(intel['attributed_groups'])}")
    if intel.get("enrichment_degraded"):
        print("  NOTE: threat feeds unavailable; enrichment degraded")

    pers = result.get("persistence", {})
    if pers.get("total"):
        print("\n-- PERSISTENCE " + "-" * 59)
        print(f"  Findings:                 {pers['total']} "
              f"({pers.get('critical_or_high', 0)} critical/high, "
              f"{pers.get('likely_automation', 0)} likely automation)")
        for f in pers.get("findings", [])[:6]:
            print(f"    [{f.get('severity', '?').upper():8s}] {f.get('mechanism')}: "
                  f"{f.get('detail', '')[:70]}")

    pb = result.get("containment_playbook", {})
    if pb.get("immediate"):
        print("\n-- CONTAINMENT (recommended, not executed) " + "-" * 31)
        for step in pb["immediate"][:5]:
            print(f"  ! {step['action']}")
        if pb.get("short_term"):
            print(f"  + {len(pb['short_term'])} short-term step(s), see --playbook")

    plan = result.get("plan")
    if not plan:
        print("\n" + result.get("note", "No plan generated."))
        print("=" * 74 + "\n")
        return

    mc = result.get("model_config", {})
    if mc:
        flags = []
        if mc.get("redacted"): flags.append("redacted")
        if mc.get("private_endpoint"): flags.append("PrivateLink")
        if mc.get("agentic"): flags.append("agentic")
        print(f"\n-- MODEL " + "-" * 65)
        print(f"  {mc.get('model_id')} in {mc.get('region')}"
              + (f"  [{', '.join(flags)}]" if flags else ""))
    tr = result.get("agent_trace")
    if tr:
        print(f"  Agent: {tr['steps_used']}/{tr['max_steps']} tool calls, "
              f"{tr['tokens']['input']:,} in / {tr['tokens']['output']:,} out tokens"
              + ("  [hit cap]" if tr.get("hit_cap") else ""))
        for c in tr.get("calls", []):
            print(f"    {c['step']}. {c['tool']}({json.dumps(c['args'])[:50]}) -> {c['result_summary'][:60]}")

    print(f"\n-- ASSESSMENT " + "-" * 60)
    print(f"  {plan.get('environment_summary', 'n/a')}")
    if plan.get("confidence_statement"):
        print(f"\n  Confidence: {plan['confidence_statement']}")

    print("\n-- HYPOTHESES " + "-" * 60)
    for h in plan.get("key_hypotheses", []):
        print(f"  - {h}")

    print("\n-- PRIORITIZED PLAN " + "-" * 54)
    for step in plan.get("investigation_plan", []):
        pri = step.get("_priority", "?").upper()
        score = step.get("_composite_score", 0)
        overdue = "  [OVERDUE]" if step.get("_overdue") else ""
        print(f"\n  [{pri} {score}/10]{overdue} Step {step.get('step')}: {step.get('action')}")
        if step.get("attack_technique_id"):
            print(f"      ATT&CK: {step['attack_technique_id']} "
                  f"{step.get('attack_technique_name', '')} "
                  f"({step.get('mitre_tactic', '')})")
        if step.get("rationale"):
            print(f"      Why: {step['rationale']}")
        dims = step.get("_dimension_scores", {})
        if dims:
            print(f"      Scores: business {dims.get('business_impact')} | "
                  f"threat {dims.get('threat_confidence')} | "
                  f"evidence {dims.get('evidence_quality')} | "
                  f"effort {dims.get('response_effort_raw')}")
        if step.get("affected_accounts"):
            print(f"      Accounts: {', '.join(step['affected_accounts'])}")

    print("\n" + "=" * 74 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="SPECTER cloud forensics orchestrator")
    parser.add_argument("--accounts", help="Comma-separated account IDs")
    parser.add_argument("--discover", action="store_true",
                        help="Enumerate accounts via AWS Organizations")
    parser.add_argument("--regions", default="us-east-1",
                        help="Comma-separated regions (default: us-east-1)")
    parser.add_argument("--role-name", default="SPECTERForensicsReadOnly",
                        help="IR role name to assume in member accounts")
    parser.add_argument("--partition", default="aws", choices=["aws", "aws-us-gov"])
    parser.add_argument("--model", default=None,
                        help=f"Bedrock model ID (default: {MODEL_ID}; env SPECTER_MODEL_ID)")
    parser.add_argument("--bedrock-region", default=None,
                        help=f"Region for Bedrock calls (default: {AWS_REGION}; env SPECTER_BEDROCK_REGION)")
    parser.add_argument("--bedrock-endpoint", default=os.environ.get("SPECTER_BEDROCK_ENDPOINT"),
                        help="PrivateLink endpoint URL for bedrock-runtime (keeps traffic off the public endpoint)")
    parser.add_argument("--redact", action="store_true",
                        help="Tokenize account IDs, ARNs, IPs, keys, and buckets before the model call")
    parser.add_argument("--agent", action="store_true",
                        help="Agentic mode: model can call read-only tools before submitting the plan")
    parser.add_argument("--max-agent-steps", type=int, default=8,
                        help="Tool-call cap in agentic mode (default: 8)")
    parser.add_argument("--window-hours", type=int, default=72)
    parser.add_argument("--token-budget", type=int, default=40_000)
    parser.add_argument("--max-workers", type=int, default=12)
    parser.add_argument("--context", default="business_context.yaml")
    parser.add_argument("--feed-dir", default="mock_feeds")
    parser.add_argument("--dry-run", action="store_true",
                        help="Collect and correlate but skip model invocation")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="Emit raw JSON instead of formatted output")
    parser.add_argument("--output", help="Write JSON result to this path")
    parser.add_argument("--report", help="Write the Markdown incident report to this path")
    parser.add_argument("--timeline", help="Write a Timesketch-compatible CSV timeline to this path")
    parser.add_argument("--playbook", help="Write the containment playbook (JSON) to this path")
    parser.add_argument("--case-id", help="Case identifier for the evidence directory")
    parser.add_argument("--no-preserve", action="store_true",
                        help="Skip writing the hashed evidence bundle to disk")
    parser.add_argument("--no-live-hunt", action="store_true",
                        help="Skip live-state persistence checks (IAM/Lambda enumeration)")
    parser.add_argument("--athena-database", help="Enable Athena backend: Glue database name")
    parser.add_argument("--athena-table", help="Athena table (CloudTrail or Security Lake)")
    parser.add_argument("--athena-output", help="s3://... location for Athena query results")
    parser.add_argument("--athena-source", default="cloudtrail",
                        choices=["cloudtrail", "security_lake"],
                        help="Athena source schema (default: cloudtrail)")
    parser.add_argument("--athena-partitions", default="ymd",
                        choices=["ymd", "timestamp", "none"],
                        help="CloudTrail table partition layout (default: ymd)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    athena_config = None
    if args.athena_database:
        from services.athena_collector import AthenaConfig
        if not (args.athena_table and args.athena_output):
            parser.error("--athena-database requires --athena-table and --athena-output")
        athena_config = AthenaConfig(
            database=args.athena_database,
            table=args.athena_table,
            output_location=args.athena_output,
            source_type=args.athena_source,
            partition_scheme=args.athena_partitions,
        )

    specter = Specter(
        partition=args.partition,
        business_context=args.context,
        feed_dir=args.feed_dir,
        max_workers=args.max_workers,
        athena_config=athena_config,
        model_id=args.model,
        bedrock_region=args.bedrock_region,
        bedrock_endpoint=args.bedrock_endpoint,
        redact=args.redact,
        agent_mode=args.agent,
        max_agent_steps=args.max_agent_steps,
    )

    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    if args.discover:
        targets = specter.broker.discover_accounts(role_name=args.role_name)
        if not targets:
            print("Organizations discovery returned nothing. "
                  "Supply --accounts explicitly.", file=sys.stderr)
            return 1
    elif args.accounts:
        targets = [
            AccountTarget(account_id=a.strip(), role_name=args.role_name)
            for a in args.accounts.split(",") if a.strip()
        ]
    else:
        parser.error("Provide --accounts or --discover")

    try:
        result = specter.run(
            targets, regions,
            window_hours=args.window_hours,
            token_budget=args.token_budget,
            skip_model=args.dry_run,
            hunt_live_state=not args.no_live_hunt,
            preserve=not args.no_preserve,
            case_id=args.case_id,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, default=str))
        print(f"Written to {args.output}")

    if args.report and result.get("incident_report"):
        Path(args.report).write_text(result["incident_report"])
        print(f"Incident report written to {args.report}")

    if args.timeline:
        pkg = result.get("evidence_package", {})
        specter.timeline.export(pkg.get("event_sample", []), pkg.get("correlation", {}),
                                args.timeline)
        print(f"Timeline written to {args.timeline}")

    if args.playbook and result.get("containment_playbook"):
        Path(args.playbook).write_text(json.dumps(result["containment_playbook"], indent=2))
        print(f"Containment playbook written to {args.playbook}")

    if result.get("preserved"):
        print(f"Evidence preserved: {result['preserved']['path']} "
              f"(manifest {result['preserved']['manifest_sha256'][:12]}...)")

    if args.as_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        render(result)
        if result.get("executive_brief"):
            print("-- EXECUTIVE BRIEF " + "-" * 55)
            print(f"  {result['executive_brief']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
