"""
Cross-source correlation.

Individual events rarely mean anything. A GetCallerIdentity call is
routine; the same call from a new IP followed four minutes later by
CreateAccessKey and then StopLogging is an intrusion. This module builds
the joins that make that sequence visible.

Correlation happens on three keys, in descending order of reliability:
  actor   principal ARN or username   (strongest)
  ip      source address              (strong; shared NAT can weaken it)
  time    proximity window            (weakest alone, valuable combined)

It also detects logging gaps, which are treated as first-class findings
rather than absences. A StopLogging/StartLogging pair defines a window
where the absence of evidence is itself the evidence.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

log = logging.getLogger(__name__)

LOGGING_DISABLE_EVENTS = {
    "StopLogging", "DeleteTrail", "DeleteFlowLogs",
    "StopConfigurationRecorder", "DeleteConfigurationRecorder",
    "DeleteDetector", "DisableSecurityHub",
}
LOGGING_ENABLE_EVENTS = {
    "StartLogging", "CreateTrail", "CreateFlowLogs",
    "StartConfigurationRecorder", "CreateDetector", "EnableSecurityHub",
}

ESCALATION_EVENTS = {
    "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
    "AttachRolePolicy", "PutRolePolicy", "CreateLoginProfile",
    "UpdateAssumeRolePolicy", "CreatePolicyVersion",
    "SetDefaultPolicyVersion", "CreateUser", "AddUserToGroup",
}
ACCESS_EVENTS = {
    "ConsoleLogin", "AssumeRole", "GetSessionToken",
    "GetFederationToken", "GetCallerIdentity",
}
EXFIL_EVENTS = {
    "GetObject", "CopyObject", "PutObject", "CreateDBSnapshot",
    "ModifySnapshotAttribute", "ModifyDBSnapshotAttribute",
    "SharedSnapshotCopy", "ModifyImageAttribute",
}


@dataclass
class LoggingGap:
    """A window where telemetry was on purpose suppressed."""

    start: str
    end: Optional[str]
    duration_minutes: Optional[float]
    disabled_by: str
    disable_event: str
    resource: str
    account: str
    region: str
    still_open: bool = False
    events_during_gap: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ActorTimeline:
    """Everything one principal did, across accounts and sources."""

    actor: str
    accounts_touched: Set[str] = field(default_factory=set)
    regions_touched: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = 0
    linked_findings: List[str] = field(default_factory=list)
    phases_observed: Set[str] = field(default_factory=set)
    cross_account: bool = False
    mfa_absent_events: int = 0

    def to_dict(self) -> dict:
        return {
            "actor": self.actor,
            "accounts_touched": sorted(self.accounts_touched),
            "regions_touched": sorted(self.regions_touched),
            "source_ips": sorted(self.source_ips),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "linked_findings": self.linked_findings,
            "phases_observed": sorted(self.phases_observed),
            "cross_account": self.cross_account,
            "mfa_absent_events": self.mfa_absent_events,
        }


class CorrelationEngine:
    """Joins evidence across sources into analyst-ready structures."""

    def __init__(self, time_window_minutes: int = 15):
        self.window = timedelta(minutes=time_window_minutes)

    def correlate(
        self,
        events: List[dict],
        findings: List[dict],
        attack_sequences: Optional[List[dict]] = None,
    ) -> dict:
        timelines = self._build_actor_timelines(events, findings)
        gaps = self._detect_logging_gaps(events)
        self._count_events_in_gaps(gaps, events)
        pivots = self._detect_cross_account_pivots(events)
        chains = self._detect_escalation_chains(events)
        sessions = self._build_session_chains(events)
        patterns = self._detect_attack_patterns(events)

        return {
            "actor_timelines": [t.to_dict() for t in timelines],
            "logging_gaps": [g.to_dict() for g in gaps],
            "cross_account_pivots": pivots,
            "escalation_chains": chains,
            "session_chains": sessions,
            "attack_patterns": patterns,
            "guardduty_attack_sequences": self._summarize_sequences(attack_sequences or []),
            "summary": {
                "distinct_actors": len(timelines),
                "cross_account_actors": sum(1 for t in timelines if t.cross_account),
                "logging_gaps_detected": len(gaps),
                "open_logging_gaps": sum(1 for g in gaps if g.still_open),
                "escalation_chains": len(chains),
                "session_chains": len(sessions),
                "attack_patterns": len(patterns),
            },
        }

    def _build_session_chains(self, events: List[dict]) -> List[dict]:
        """Link AssumeRole calls to everything done under the resulting session.

        CloudTrail records the temp access key in the AssumeRole response, and
        every later call under that session carries the same key in
        userIdentity.accessKeyId. Join on the key and a pile of unrelated
        events becomes "svc assumed Admin, then did A, B, C." Without this,
        role pivots break the trail.
        """
        minted: Dict[str, dict] = {}
        for ev in events:
            if ev.get("eventName") not in ("AssumeRole", "AssumeRoleWithSAML",
                                           "AssumeRoleWithWebIdentity"):
                continue
            creds = (ev.get("responseElements") or {}).get("credentials") or {}
            key = creds.get("accessKeyId")
            if key:
                minted[key] = ev
        if not minted:
            return []

        under: Dict[str, List[dict]] = defaultdict(list)
        for ev in events:
            key = ev.get("accessKeyId") or (ev.get("userIdentity") or {}).get("accessKeyId")
            if key in minted and ev is not minted[key]:
                under[key].append(ev)

        chains = []
        for key, origin in minted.items():
            actions = sorted(under.get(key, []), key=lambda e: e.get("eventTime", ""))
            params = origin.get("requestParameters") or {}
            chains.append({
                "session_key": key[:8] + "..." if len(key) > 8 else key,
                "assumed_by": _actor(origin),
                "assumed_at": origin.get("eventTime"),
                "role": params.get("roleArn") if isinstance(params, dict) else None,
                "source_ip": origin.get("sourceIPAddress"),
                "action_count": len(actions),
                "actions": [{"time": a.get("eventTime"), "event": a.get("eventName"),
                             "account": a.get("account"), "region": a.get("awsRegion")}
                            for a in actions[:25]],
                "notable": sorted({a.get("eventName") for a in actions
                                   if a.get("eventName") in ESCALATION_EVENTS
                                   or a.get("eventName") in LOGGING_DISABLE_EVENTS
                                   or a.get("eventName") in EXFIL_EVENTS}),
            })
        return sorted(chains, key=lambda c: -c["action_count"])

    def _detect_attack_patterns(self, events: List[dict]) -> List[dict]:
        """Name multi-event clusters that match AWS CIRT casework patterns.

        Heuristics, not proof. The point is to put a name on a cluster so
        the analyst knows what to go verify.
        """
        patterns = []
        by_actor: Dict[str, List[dict]] = defaultdict(list)
        for ev in events:
            a = _actor(ev)
            if a:
                by_actor[a].append(ev)

        for actor, evs in by_actor.items():
            names = [e.get("eventName") for e in evs]
            regions = {e.get("awsRegion") for e in evs if e.get("awsRegion")}
            counts = Counter(names)

            runs = counts.get("RunInstances", 0)
            if runs >= 3:
                patterns.append(_pattern("cryptomining_indicator", actor, evs,
                    f"{runs} RunInstances across {len(regions)} region(s)",
                    "T1496", "Resource Hijacking",
                    "high" if runs >= 10 or len(regions) >= 3 else "medium"))

            deletes = counts.get("DeleteObject", 0) + counts.get("DeleteObjects", 0)
            tamper = sum(counts.get(n, 0) for n in
                         ("PutBucketLifecycle", "PutBucketLifecycleConfiguration",
                          "PutBucketVersioning", "DeleteBucketPolicy"))
            if deletes >= 20 or (tamper and deletes):
                patterns.append(_pattern("s3_ransomware_indicator", actor, evs,
                    f"{deletes} delete calls, {tamper} lifecycle/versioning changes",
                    "T1485", "Data Destruction", "critical"))

            shares = sum(counts.get(n, 0) for n in
                         ("ModifySnapshotAttribute", "ModifyDBSnapshotAttribute",
                          "ModifyImageAttribute", "ModifyDBClusterSnapshotAttribute"))
            if shares:
                patterns.append(_pattern("snapshot_exfiltration", actor, evs,
                    f"{shares} snapshot/image sharing change(s)",
                    "T1537", "Transfer Data to Cloud Account", "high"))

            disc = sum(1 for n in names if n and (n.startswith("List") or
                                                  n.startswith("Describe") or
                                                  n.startswith("GetAccount")))
            if disc >= 30:
                patterns.append(_pattern("discovery_burst", actor, evs,
                    f"{disc} enumeration calls",
                    "T1580", "Cloud Infrastructure Discovery", "medium"))

            secrets = sum(counts.get(n, 0) for n in
                          ("GetSecretValue", "BatchGetSecretValue", "GetParameter",
                           "GetParameters", "GetParametersByPath", "Decrypt"))
            if secrets >= 5:
                patterns.append(_pattern("secrets_harvesting", actor, evs,
                    f"{secrets} secret/parameter retrievals",
                    "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API",
                    "high"))

            expose = sum(counts.get(n, 0) for n in
                         ("PutBucketAcl", "PutBucketPolicy", "PutObjectAcl",
                          "AuthorizeSecurityGroupIngress", "ModifyDBInstance"))
            if expose >= 3:
                patterns.append(_pattern("resource_exposure", actor, evs,
                    f"{expose} exposure-related change(s)",
                    "T1562.007", "Impair Defenses: Disable or Modify Cloud Firewall",
                    "high"))

        return sorted(patterns, key=lambda p: {"critical": 0, "high": 1,
                                               "medium": 2}.get(p["severity"], 3))

    # ------------------------------------------------------------------

    def _build_actor_timelines(
        self, events: List[dict], findings: List[dict]
    ) -> List[ActorTimeline]:
        by_actor: Dict[str, ActorTimeline] = {}

        for ev in events:
            actor = _actor(ev)
            if not actor:
                continue
            tl = by_actor.setdefault(actor, ActorTimeline(actor=actor))
            tl.event_count += 1

            acct = ev.get("account") or ev.get("recipientAccountId")
            if acct:
                tl.accounts_touched.add(str(acct))
            region = ev.get("awsRegion")
            if region:
                tl.regions_touched.add(region)
            ip = ev.get("sourceIPAddress")
            if ip:
                tl.source_ips.add(ip)

            ts = ev.get("eventTime")
            if ts:
                if tl.first_seen is None or ts < tl.first_seen:
                    tl.first_seen = ts
                if tl.last_seen is None or ts > tl.last_seen:
                    tl.last_seen = ts

            name = ev.get("eventName", "")
            if name in ACCESS_EVENTS:
                tl.phases_observed.add("initial_access")
            if name in ESCALATION_EVENTS:
                tl.phases_observed.add("privilege_escalation")
            if name in LOGGING_DISABLE_EVENTS:
                tl.phases_observed.add("defense_evasion")
            if name in EXFIL_EVENTS:
                tl.phases_observed.add("collection_exfiltration")
            if name in {"ListUsers", "ListRoles", "ListBuckets", "DescribeInstances"}:
                tl.phases_observed.add("discovery")

            if ev.get("mfaAuthenticated") in ("false", False):
                tl.mfa_absent_events += 1

        # Join GuardDuty findings by actor and by IP
        for finding in findings:
            f_actor = _finding_actor(finding)
            f_id = finding.get("Id", finding.get("id", ""))
            if f_actor and f_actor in by_actor:
                by_actor[f_actor].linked_findings.append(f_id)
                continue
            f_ips = _finding_ips(finding)
            for tl in by_actor.values():
                if tl.source_ips & f_ips:
                    tl.linked_findings.append(f_id)
                    break

        for tl in by_actor.values():
            tl.cross_account = len(tl.accounts_touched) > 1

        return sorted(by_actor.values(), key=lambda t: -t.event_count)

    def _detect_logging_gaps(self, events: List[dict]) -> List[LoggingGap]:
        """Pair disable/enable events into concrete gap windows."""
        gaps: List[LoggingGap] = []
        pending: Dict[str, dict] = {}

        ordered = sorted(events, key=lambda e: e.get("eventTime", ""))
        for ev in ordered:
            name = ev.get("eventName", "")
            resource = _target_resource(ev)
            key = f"{ev.get('account', '')}:{ev.get('awsRegion', '')}:{resource}"

            if name in LOGGING_DISABLE_EVENTS:
                pending[key] = ev
            elif name in LOGGING_ENABLE_EVENTS and key in pending:
                start_ev = pending.pop(key)
                gaps.append(
                    LoggingGap(
                        start=start_ev.get("eventTime", ""),
                        end=ev.get("eventTime"),
                        duration_minutes=_minutes_between(
                            start_ev.get("eventTime"), ev.get("eventTime")
                        ),
                        disabled_by=_actor(start_ev),
                        disable_event=start_ev.get("eventName", ""),
                        resource=resource,
                        account=str(start_ev.get("account", "")),
                        region=str(start_ev.get("awsRegion", "")),
                    )
                )

        # Anything unpaired is an open gap, which is worse than a closed one
        for key, start_ev in pending.items():
            gaps.append(
                LoggingGap(
                    start=start_ev.get("eventTime", ""),
                    end=None,
                    duration_minutes=None,
                    disabled_by=_actor(start_ev),
                    disable_event=start_ev.get("eventName", ""),
                    resource=_target_resource(start_ev),
                    account=str(start_ev.get("account", "")),
                    region=str(start_ev.get("awsRegion", "")),
                    still_open=True,
                )
            )
        return gaps

    @staticmethod
    def _count_events_in_gaps(gaps: List[LoggingGap], events: List[dict]) -> None:
        """How much activity happened while logging was off.

        Any non-zero count here is significant: it means the attacker was
        active in a window they had on purpose darkened, and whatever is
        visible is a floor, not a complete picture.
        """
        for gap in gaps:
            if not gap.start or not gap.end:
                continue
            count = 0
            for ev in events:
                ts = ev.get("eventTime")
                if ts and gap.start < ts < gap.end:
                    count += 1
            gap.events_during_gap = count

    @staticmethod
    def _detect_cross_account_pivots(events: List[dict]) -> List[dict]:
        """Find AssumeRole calls that cross an account boundary."""
        pivots = []
        for ev in events:
            if ev.get("eventName") != "AssumeRole":
                continue
            params = ev.get("requestParameters") or {}
            role_arn = params.get("roleArn") if isinstance(params, dict) else None
            if not role_arn or not isinstance(role_arn, str):
                continue
            parts = role_arn.split(":")
            target_account = parts[4] if len(parts) > 4 else ""
            source_account = str(ev.get("account", ""))
            if target_account and source_account and target_account != source_account:
                pivots.append({
                    "time": ev.get("eventTime"),
                    "actor": _actor(ev),
                    "source_account": source_account,
                    "target_account": target_account,
                    "target_role": role_arn,
                    "source_ip": ev.get("sourceIPAddress"),
                })
        return pivots

    def _detect_escalation_chains(self, events: List[dict]) -> List[dict]:
        """Access followed by privilege escalation within the correlation window.

        This is the single highest-value pattern in cloud IR: the
        individual calls are unremarkable, the sequence is not.
        """
        chains = []
        by_actor: Dict[str, List[dict]] = defaultdict(list)
        for ev in events:
            actor = _actor(ev)
            if actor:
                by_actor[actor].append(ev)

        for actor, actor_events in by_actor.items():
            actor_events.sort(key=lambda e: e.get("eventTime", ""))
            for i, ev in enumerate(actor_events):
                if ev.get("eventName") not in ACCESS_EVENTS:
                    continue
                access_time = _parse_time(ev.get("eventTime"))
                if not access_time:
                    continue
                followers = []
                for later in actor_events[i + 1:]:
                    later_time = _parse_time(later.get("eventTime"))
                    if not later_time or later_time - access_time > self.window:
                        break
                    if later.get("eventName") in ESCALATION_EVENTS:
                        followers.append({
                            "event": later.get("eventName"),
                            "time": later.get("eventTime"),
                        })
                if followers:
                    chains.append({
                        "actor": actor,
                        "access_event": ev.get("eventName"),
                        "access_time": ev.get("eventTime"),
                        "source_ip": ev.get("sourceIPAddress"),
                        "mfa": ev.get("mfaAuthenticated"),
                        "escalation_events": followers,
                        "window_minutes": self.window.total_seconds() / 60,
                    })
        return chains

    @staticmethod
    def _summarize_sequences(sequences: List[dict]) -> List[dict]:
        """Surface GuardDuty Extended Threat Detection sequences.

        GuardDuty already performs multi-stage correlation with ATT&CK
        tactics attached. Where those exist they are authoritative and
        should anchor the plan rather than be re-derived.
        """
        out = []
        for seq in sequences:
            detection = (seq.get("Service", {}) or {}).get("Detection", {}) or {}
            sequence = detection.get("Sequence", {}) or {}
            out.append({
                "id": seq.get("Id"),
                "type": seq.get("Type"),
                "severity": seq.get("Severity"),
                "title": seq.get("Title"),
                "description": _truncate(seq.get("Description", ""), 400),
                "account": seq.get("_specter_account"),
                "region": seq.get("_specter_region"),
                "signal_count": len(sequence.get("Signals", []) or []),
                "actors": [a.get("Id") for a in (sequence.get("Actors", []) or [])],
            })
        return out


# ----------------------------------------------------------------------


def _actor(event: dict) -> str:
    actor = event.get("actor")
    if isinstance(actor, dict):
        return actor.get("arn") or actor.get("userName") or ""
    ident = event.get("userIdentity", {}) or {}
    return ident.get("arn") or ident.get("userName") or ident.get("principalId") or ""


def _pattern(kind, actor, evs, detail, technique, technique_name, severity) -> dict:
    times = sorted(e.get("eventTime", "") for e in evs if e.get("eventTime"))
    return {
        "pattern": kind, "actor": actor, "detail": detail,
        "technique": technique, "technique_name": technique_name, "severity": severity,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "event_count": len(evs),
        "accounts": sorted({str(e.get("account")) for e in evs if e.get("account")}),
        "ttc_url": f"https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/{technique}.html",
    }


def _finding_actor(finding: dict) -> str:
    resource = finding.get("Resource", {}) or {}
    details = resource.get("AccessKeyDetails", {}) or {}
    return details.get("UserName") or details.get("PrincipalId") or ""


def _finding_ips(finding: dict) -> Set[str]:
    ips: Set[str] = set()
    service = finding.get("Service", {}) or {}
    action = service.get("Action", {}) or {}
    for key in ("AwsApiCallAction", "NetworkConnectionAction", "PortProbeAction"):
        block = action.get(key, {}) or {}
        remote = block.get("RemoteIpDetails", {}) or {}
        if remote.get("IpAddressV4"):
            ips.add(remote["IpAddressV4"])
    return ips


def _target_resource(event: dict) -> str:
    params = event.get("requestParameters") or {}
    if isinstance(params, dict):
        for key in ("name", "trailName", "flowLogIds", "detectorId",
                    "configurationRecorderName"):
            if key in params:
                return str(params[key])
    return "unknown"


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _minutes_between(start: Optional[str], end: Optional[str]) -> Optional[float]:
    a, b = _parse_time(start), _parse_time(end)
    if not a or not b:
        return None
    return round((b - a).total_seconds() / 60.0, 1)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."
