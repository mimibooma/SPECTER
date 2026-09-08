"""
Persistence hunting.

After credential compromise the first question is: what did they leave
behind? This checks the persistence mechanisms that show up repeatedly in
real AWS intrusions. Each maps to a technique in the AWS Threat Technique
Catalog (TTC), which comes from AWS CIRT casework rather than theory.

Two groups of checks:

  Event-based   scan the collected CloudTrail window for creation/mutation
                calls that establish persistence. Cheap, no extra API calls.
  State-based   query current account state for artifacts that exist now
                regardless of when they were created. Costs API calls but
                catches persistence established before the collection window.

Both produce PersistenceFinding records with the same shape so downstream
code treats them uniformly.

Ref: https://aws-samples.github.io/threat-technique-catalog-for-aws/
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

log = logging.getLogger(__name__)

TTC_BASE = "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques"

# Persistence-establishing API calls by mechanism. IDs are ATT&CK; the TTC
# extends these with AWS-specific sub-techniques.
PERSISTENCE_EVENTS = {
    "iam_backdoor": {
        "events": {"CreateUser", "CreateAccessKey", "CreateLoginProfile",
                   "AttachUserPolicy", "PutUserPolicy", "AddUserToGroup"},
        "technique": "T1136.003", "name": "Create Account: Cloud Account",
        "severity": "high",
    },
    "role_trust_modification": {
        "events": {"UpdateAssumeRolePolicy", "CreateRole"},
        "technique": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "severity": "critical",
    },
    "policy_backdoor": {
        "events": {"CreatePolicyVersion", "SetDefaultPolicyVersion",
                   "AttachRolePolicy", "PutRolePolicy"},
        "technique": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles",
        "severity": "high",
    },
    "lambda_persistence": {
        "events": {"CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration",
                   "AddPermission", "CreateEventSourceMapping"},
        "technique": "T1546", "name": "Event Triggered Execution",
        "severity": "high",
    },
    "eventbridge_persistence": {
        "events": {"PutRule", "PutTargets"},
        "technique": "T1546", "name": "Event Triggered Execution",
        "severity": "medium",
    },
    "compute_persistence": {
        "events": {"RunInstances", "CreateKeyPair", "ImportKeyPair", "ModifyInstanceAttribute"},
        "technique": "T1578", "name": "Modify Cloud Compute Infrastructure",
        "severity": "medium",
    },
    "ssm_persistence": {
        "events": {"CreateDocument", "UpdateDocument", "CreateAssociation", "SendCommand"},
        "technique": "T1651", "name": "Cloud Administration Command",
        "severity": "high",
    },
    "identity_provider": {
        "events": {"CreateSAMLProvider", "UpdateSAMLProvider", "CreateOpenIDConnectProvider"},
        "technique": "T1556", "name": "Modify Authentication Process",
        "severity": "critical",
    },
    "mfa_removal": {
        "events": {"DeactivateMFADevice", "DeleteVirtualMFADevice"},
        "technique": "T1556.006",
        "name": "Modify Authentication Process: Multi-Factor Authentication",
        "severity": "critical",
    },
}

# Principals that create resources all day. Still recorded, but flagged as
# probable automation so they don't drown the signal.
AUTOMATION_HINTS = ("cloudformation", "terraform", "pulumi", "cdk", "ci-", "cicd",
                    "deploy", "pipeline", "github-actions", "jenkins")


@dataclass
class PersistenceFinding:
    mechanism: str
    technique: str
    technique_name: str
    severity: str
    actor: str
    account: str
    region: str
    time: Optional[str]
    detail: str
    event_name: Optional[str] = None
    resource: Optional[str] = None
    likely_automation: bool = False
    source: str = "cloudtrail"  # cloudtrail | live_state
    ttc_url: str = ""

    def __post_init__(self):
        if not self.ttc_url:
            self.ttc_url = f"{TTC_BASE}/{self.technique}.html"

    def to_dict(self) -> dict:
        return asdict(self)


class PersistenceHunter:

    def __init__(self, broker=None, max_workers: int = 8):
        self.broker = broker
        self.max_workers = max_workers

    def hunt_events(self, events: List[dict],
                    suspicious_actors: Optional[Set[str]] = None) -> List[PersistenceFinding]:
        """Flag persistence-establishing calls in the collected window.

        Calls by suspicious_actors keep their full severity; calls from
        things that look like deploy pipelines get downgraded to low unless
        the principal is already on the suspect list.
        """
        findings: List[PersistenceFinding] = []
        suspicious = {a.lower() for a in (suspicious_actors or set())}

        for ev in events:
            name = ev.get("eventName", "")
            for mechanism, spec in PERSISTENCE_EVENTS.items():
                if name not in spec["events"]:
                    continue
                actor = _actor(ev)
                is_auto = _looks_like_automation(actor, ev.get("userAgent", ""))
                severity = spec["severity"]
                if is_auto and actor.lower() not in suspicious:
                    severity = "low"
                findings.append(PersistenceFinding(
                    mechanism=mechanism, technique=spec["technique"],
                    technique_name=spec["name"], severity=severity, actor=actor,
                    account=str(ev.get("account", "")), region=str(ev.get("awsRegion", "")),
                    time=ev.get("eventTime"), event_name=name, resource=_target(ev),
                    detail=_describe(mechanism, name, ev), likely_automation=is_auto,
                ))
                break
        return sorted(findings, key=lambda f: (_sev_rank(f.severity), f.time or ""))

    def hunt_state(self, targets, regions: List[str],
                   lookback_days: int = 30) -> List[PersistenceFinding]:
        """Query live state for persistence that predates the collection window.

        Checks: recently created IAM users, users with more than one active
        key, roles trusting external accounts or wildcards, Lambda functions
        modified recently. Needs the broker.
        """
        if not self.broker:
            log.info("no broker; skipping live-state persistence checks")
            return []
        findings: List[PersistenceFinding] = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futs = {pool.submit(self._check_account, t, regions, cutoff): t for t in targets}
            for fut in as_completed(futs):
                try:
                    findings.extend(fut.result())
                except Exception as exc:  # noqa: BLE001
                    log.warning("state hunt failed for %s: %s", futs[fut].account_id, exc)
        return sorted(findings, key=lambda f: (_sev_rank(f.severity), f.time or ""))

    def _check_account(self, target, regions, cutoff) -> List[PersistenceFinding]:
        out: List[PersistenceFinding] = []
        # IAM is global but the endpoint is partition-specific
        iam_region = "us-gov-west-1" if self.broker.partition == "aws-us-gov" else "us-east-1"
        session = self.broker.session_for(target, region=iam_region)
        iam = session.client("iam")
        acct = target.account_id

        # list_access_keys is one call per user. Cap it so a 10k-user account
        # doesn't turn into 10k API calls; the credential report is the right
        # tool past that scale and is noted in the finding.
        MAX_USERS_FOR_KEY_CHECK = 500
        checked = 0
        try:
            for page in iam.get_paginator("list_users").paginate():
                for user in page.get("Users", []):
                    created = user.get("CreateDate")
                    uname = user.get("UserName", "")
                    if created and created >= cutoff:
                        out.append(PersistenceFinding(
                            mechanism="iam_backdoor", technique="T1136.003",
                            technique_name="Create Account: Cloud Account",
                            severity="high", actor="(live state)", account=acct,
                            region="global", time=created.isoformat(), resource=uname,
                            source="live_state",
                            detail=f"IAM user '{uname}' created {created:%Y-%m-%d}, inside lookback",
                        ))
                    if checked >= MAX_USERS_FOR_KEY_CHECK:
                        if checked == MAX_USERS_FOR_KEY_CHECK:
                            log.warning("%s: >%d IAM users; skipping per-user key check. "
                                        "Use the IAM credential report for full coverage.",
                                        acct, MAX_USERS_FOR_KEY_CHECK)
                            checked += 1
                        continue
                    checked += 1
                    keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                    active = [k for k in keys if k.get("Status") == "Active"]
                    if len(active) > 1:
                        out.append(PersistenceFinding(
                            mechanism="iam_backdoor", technique="T1098.001",
                            technique_name="Account Manipulation: Additional Cloud Credentials",
                            severity="high", actor="(live state)", account=acct,
                            region="global", time=None, resource=uname, source="live_state",
                            detail=f"IAM user '{uname}' has {len(active)} active access keys",
                        ))
        except Exception as exc:  # noqa: BLE001
            log.warning("user enum failed %s: %s", acct, exc)

        try:
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    rname = role.get("RoleName", "")
                    ext = _external_principals(role.get("AssumeRolePolicyDocument", {}), acct)
                    if ext:
                        out.append(PersistenceFinding(
                            mechanism="role_trust_modification", technique="T1098.003",
                            technique_name="Account Manipulation: Additional Cloud Roles",
                            severity="critical" if "*" in ext else "high",
                            actor="(live state)", account=acct, region="global",
                            time=None, resource=rname, source="live_state",
                            detail=f"Role '{rname}' trusts external principals: "
                                   f"{', '.join(sorted(ext)[:5])}",
                        ))
        except Exception as exc:  # noqa: BLE001
            log.warning("role enum failed %s: %s", acct, exc)

        for region in regions:
            try:
                lam = self.broker.session_for(target, region=region).client("lambda")
                for page in lam.get_paginator("list_functions").paginate():
                    for fn in page.get("Functions", []):
                        mod = fn.get("LastModified", "")
                        try:
                            mod_dt = datetime.fromisoformat(mod.replace("Z", "+00:00"))
                        except (ValueError, AttributeError):
                            continue
                        if mod_dt >= cutoff:
                            out.append(PersistenceFinding(
                                mechanism="lambda_persistence", technique="T1546",
                                technique_name="Event Triggered Execution", severity="medium",
                                actor="(live state)", account=acct, region=region, time=mod,
                                resource=fn.get("FunctionName"), source="live_state",
                                detail=f"Lambda '{fn.get('FunctionName')}' modified "
                                       f"{mod_dt:%Y-%m-%d}; check code and triggers",
                            ))
            except Exception as exc:  # noqa: BLE001
                log.warning("lambda enum failed %s/%s: %s", acct, region, exc)
        return out


def summarize(findings: List[PersistenceFinding]) -> dict:
    by_mech: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_mech[f.mechanism] = by_mech.get(f.mechanism, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "by_mechanism": by_mech,
        "by_severity": by_sev,
        "critical_or_high": sum(1 for f in findings if f.severity in ("critical", "high")),
        "likely_automation": sum(1 for f in findings if f.likely_automation),
        "findings": [f.to_dict() for f in findings],
    }


def _actor(ev: dict) -> str:
    a = ev.get("actor")
    if isinstance(a, dict):
        return a.get("arn") or a.get("userName") or ""
    ident = ev.get("userIdentity") or {}
    return ident.get("arn") or ident.get("userName") or ""


def _target(ev: dict) -> Optional[str]:
    p = ev.get("requestParameters")
    if not isinstance(p, dict):
        return None
    for k in ("userName", "roleName", "policyArn", "functionName", "name",
              "instanceId", "keyName", "documentName", "ruleName"):
        if k in p:
            return str(p[k])
    return None


def _describe(mechanism: str, event: str, ev: dict) -> str:
    tgt = _target(ev)
    base = {
        "iam_backdoor": f"{event} establishes or extends an IAM identity",
        "role_trust_modification": f"{event} changes who can assume a role",
        "policy_backdoor": f"{event} alters effective permissions",
        "lambda_persistence": f"{event} creates or modifies code with a trigger",
        "eventbridge_persistence": f"{event} wires an event to a target",
        "compute_persistence": f"{event} establishes attacker-controlled compute",
        "ssm_persistence": f"{event} enables remote execution on managed instances",
        "identity_provider": f"{event} alters federation trust",
        "mfa_removal": f"{event} weakens authentication on an identity",
    }.get(mechanism, event)
    return base + (f" (target: {tgt})" if tgt else "")


def _looks_like_automation(actor: str, user_agent: str) -> bool:
    hay = f"{actor} {user_agent}".lower()
    return any(h in hay for h in AUTOMATION_HINTS)


def _external_principals(trust_doc: dict, own_account: str) -> Set[str]:
    found: Set[str] = set()
    for stmt in trust_doc.get("Statement", []) or []:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            found.add("*")
            continue
        if not isinstance(principal, dict):
            continue
        aws = principal.get("AWS", [])
        if isinstance(aws, str):
            aws = [aws]
        for p in aws:
            if p == "*":
                found.add("*")
            elif own_account not in str(p):
                found.add(str(p))
    return found


def _sev_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 4)
