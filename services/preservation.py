"""
Evidence preservation and containment guidance.

Two things an IR tool needs that an analysis tool doesn't:

  1. A preserved, hashed copy of what was collected. If this goes to legal
     or a regulator, "here's what the tool saw, here's the hash, here's
     when" is what makes it evidence. NIST 800-86.

  2. Containment steps the analyst can actually run. SPECTER stays read-only
     by design, but it can hand over the exact commands. The analyst pulls
     the trigger; the tool never does.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)


class EvidencePreserver:
    """Write collected evidence to disk with integrity hashes."""

    def __init__(self, out_dir: str = "evidence"):
        self.out_dir = Path(out_dir)

    def preserve(self, bundle, correlation: dict, enrichment: dict,
                 landscape: dict, case_id: Optional[str] = None,
                 agent_trace: Optional[dict] = None) -> dict:
        case_id = case_id or datetime.now(timezone.utc).strftime("specter-%Y%m%dT%H%M%SZ")
        case_id = _safe_case_id(case_id)
        case_dir = (self.out_dir / case_id).resolve()
        if self.out_dir.resolve() not in case_dir.parents:
            raise ValueError(f"case_id resolves outside evidence dir: {case_id!r}")
        case_dir.mkdir(parents=True, exist_ok=True)

        artifacts = {
            "events.json": bundle.events,
            "guardduty_findings.json": bundle.findings,
            "attack_sequences.json": bundle.attack_sequences,
            "correlation.json": correlation,
            "enrichment.json": enrichment,
            "landscape.json": landscape,
            "collection_stats.json": bundle.stats.to_dict(),
        }
        if agent_trace:
            artifacts["agent_trace.json"] = agent_trace
        manifest = {
            "case_id": case_id,
            "preserved_at": datetime.now(timezone.utc).isoformat(),
            "collection_window": {
                "start": bundle.window_start.isoformat() if bundle.window_start else None,
                "end": bundle.window_end.isoformat() if bundle.window_end else None,
            },
            "artifacts": {},
        }
        for name, data in artifacts.items():
            raw = json.dumps(data, indent=2, sort_keys=True, default=str).encode()
            (case_dir / name).write_bytes(raw)
            manifest["artifacts"][name] = {"sha256": hashlib.sha256(raw).hexdigest(),
                                           "bytes": len(raw)}

        manifest_raw = json.dumps(manifest, indent=2, sort_keys=True).encode()
        (case_dir / "MANIFEST.json").write_bytes(manifest_raw)
        manifest["manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()
        (case_dir / "CHAIN_OF_CUSTODY.txt").write_text(_custody_note(manifest))

        log.info("evidence preserved to %s (%d artifacts)", case_dir, len(artifacts))
        return {"case_id": case_id, "path": str(case_dir),
                "manifest_sha256": manifest["manifest_sha256"],
                "artifact_count": len(artifacts)}

    @staticmethod
    def verify(case_dir: str) -> dict:
        d = Path(case_dir)
        manifest = json.loads((d / "MANIFEST.json").read_text())
        results = {}
        for name, meta in manifest.get("artifacts", {}).items():
            p = d / name
            if not p.exists():
                results[name] = "MISSING"
                continue
            actual = hashlib.sha256(p.read_bytes()).hexdigest()
            results[name] = "OK" if actual == meta["sha256"] else "MODIFIED"
        return {"case_id": manifest.get("case_id"), "results": results,
                "intact": all(v == "OK" for v in results.values())}


def _safe_case_id(raw: str) -> str:
    """Keep case IDs filesystem-safe. Strips anything that isn't alnum, dash,
    underscore, or dot, and refuses path separators outright."""
    if "/" in raw or "\\" in raw or ".." in raw:
        raise ValueError(f"case_id may not contain path separators: {raw!r}")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", raw).strip("._")
    if not cleaned:
        raise ValueError(f"case_id has no usable characters: {raw!r}")
    return cleaned[:128]


def _custody_note(manifest: dict) -> str:
    lines = [
        "SPECTER EVIDENCE PRESERVATION RECORD",
        "=" * 50,
        f"Case ID:       {manifest['case_id']}",
        f"Preserved:     {manifest['preserved_at']}",
        f"Window start:  {manifest['collection_window']['start']}",
        f"Window end:    {manifest['collection_window']['end']}",
        "",
        "Artifacts (SHA-256):",
    ]
    for name, meta in manifest["artifacts"].items():
        lines.append(f"  {meta['sha256']}  {name}  ({meta['bytes']:,} bytes)")
    lines += [
        "",
        "Generated automatically at collection time. To re-verify:",
        "  python -c \"from services.preservation import EvidencePreserver;"
        " print(EvidencePreserver.verify('<this dir>'))\"",
        "Hashes cover the JSON serialization with sorted keys.",
        "",
        "Handled by: ________________________   Date: ______________",
        "Transferred to: ____________________   Date: ______________",
    ]
    return "\n".join(lines) + "\n"


class ContainmentAdvisor:
    """Exact containment commands for the analyst to review and run.

    Recommendations only. SPECTER never executes any of this. Each step
    carries a one-line rationale so the analyst knows why before how.
    """

    def build_playbook(self, correlation: dict, persistence: dict,
                       plan: Optional[dict] = None) -> dict:
        immediate: List[dict] = []
        short_term: List[dict] = []
        verify: List[dict] = []

        actors = set()
        for c in correlation.get("escalation_chains", []):
            actors.add(c.get("actor", ""))
        for s in correlation.get("session_chains", []):
            if s.get("notable"):
                actors.add(s.get("assumed_by", ""))
        for p in correlation.get("attack_patterns", []):
            if p.get("severity") in ("critical", "high"):
                actors.add(p.get("actor", ""))
        actors.discard("")

        for arn in sorted(actors):
            kind, name = _parse_arn(arn)
            if kind == "user":
                immediate.append({
                    "action": f"Disable all access keys for IAM user {name}",
                    "why": "Principal appears in an escalation chain or high-severity pattern",
                    "commands": [
                        f"aws iam list-access-keys --user-name {name}",
                        "# for each AccessKeyId returned:",
                        f"aws iam update-access-key --user-name {name} "
                        f"--access-key-id <KEY_ID> --status Inactive",
                    ],
                    "reversible": True,
                })
                immediate.append({
                    "action": f"Attach explicit deny-all to IAM user {name}",
                    "why": "Blocks console and API without deleting the identity (keeps evidence)",
                    "commands": [
                        f"aws iam put-user-policy --user-name {name} "
                        f"--policy-name SPECTER-Containment-Deny "
                        f"--policy-document '{_DENY_ALL}'",
                    ],
                    "reversible": True,
                })
            elif kind == "role":
                immediate.append({
                    "action": f"Revoke active sessions for role {name}",
                    "why": "Invalidates temp credentials issued before now",
                    "commands": [
                        f"aws iam put-role-policy --role-name {name} "
                        f"--policy-name SPECTER-RevokeOlderSessions "
                        f"--policy-document '{_revoke_sessions_policy()}'",
                    ],
                    "reversible": True,
                })

        for g in correlation.get("logging_gaps", []):
            if g.get("still_open"):
                immediate.append({
                    "action": f"Re-enable logging on {g.get('resource')}",
                    "why": "Trail is still off; every minute is unrecorded",
                    "commands": [
                        f"aws cloudtrail start-logging --name {g.get('resource')} "
                        f"--region {g.get('region', 'us-east-1')}",
                    ],
                    "reversible": True,
                })

        for f in persistence.get("findings", []):
            if f.get("severity") not in ("critical", "high"):
                continue
            mech, res, region = f.get("mechanism"), f.get("resource"), f.get("region", "us-east-1")
            if mech == "role_trust_modification" and res:
                short_term.append({
                    "action": f"Review and restore trust policy on role {res}",
                    "why": f.get("detail", ""),
                    "commands": [
                        f"aws iam get-role --role-name {res} --query 'Role.AssumeRolePolicyDocument'",
                        "# compare against IaC / last known-good, then:",
                        f"aws iam update-assume-role-policy --role-name {res} "
                        f"--policy-document file://trust-known-good.json",
                    ],
                    "reversible": True,
                })
            elif mech == "lambda_persistence" and res:
                short_term.append({
                    "action": f"Inspect Lambda function {res}",
                    "why": f.get("detail", ""),
                    "commands": [
                        f"aws lambda get-function --function-name {res} --region {region}",
                        f"aws lambda list-event-source-mappings --function-name {res} --region {region}",
                        "# if malicious, zero the concurrency before deleting:",
                        f"aws lambda put-function-concurrency --function-name {res} "
                        f"--reserved-concurrent-executions 0 --region {region}",
                    ],
                    "reversible": True,
                })
            elif mech == "iam_backdoor" and res and f.get("source") == "live_state":
                short_term.append({
                    "action": f"Review IAM user {res}",
                    "why": f.get("detail", ""),
                    "commands": [
                        f"aws iam get-user --user-name {res}",
                        f"aws iam list-access-keys --user-name {res}",
                        f"aws iam list-attached-user-policies --user-name {res}",
                    ],
                    "reversible": True,
                })
            elif mech == "mfa_removal":
                immediate.append({
                    "action": f"Re-enroll MFA for {f.get('resource') or f.get('actor')}",
                    "why": "MFA was removed; identity is weaker than policy assumes",
                    "commands": ["# coordinate with account owner; MFA re-enrollment is interactive"],
                    "reversible": False,
                })

        verify.append({
            "action": "Confirm no new credentials since containment",
            "why": "Attackers with a foothold will try to come back",
            "commands": [
                "aws iam generate-credential-report && sleep 5 && "
                "aws iam get-credential-report --query Content --output text | base64 -d",
            ],
        })
        verify.append({
            "action": "Re-run SPECTER over the same window plus containment time",
            "why": "Confirms the plan reordered and no new chains appeared",
            "commands": ["python specter.py --accounts <ids> --window-hours 24 --dry-run"],
        })

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "compromised_principals": sorted(actors),
            "immediate": immediate,
            "short_term": short_term,
            "verify": verify,
            "disclaimer": (
                "Recommendations generated from correlated evidence. SPECTER did "
                "not execute any of them. Review each against your environment "
                "and change control before running."
            ),
        }


_DENY_ALL = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
}, separators=(",", ":"))


def _revoke_sessions_policy() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}},
        }],
    }, separators=(",", ":"))


def _parse_arn(arn: str):
    if ":user/" in arn:
        return "user", arn.split(":user/")[-1]
    if ":assumed-role/" in arn:
        return "role", arn.split(":assumed-role/")[-1].split("/")[0]
    if ":role/" in arn:
        return "role", arn.split(":role/")[-1]
    return "unknown", arn
