"""
Multi-account evidence collection with pre-model filtering.

This module exists because of one hard constraint: a single active AWS
account can produce hundreds of megabytes of CloudTrail per day, and no
language model can be handed that. Everything here is about reducing raw
volume to a defensible, high-signal subset *before* any inference cost is
paid.

The reduction is tiered, cheapest filter first:

  Tier 1  Time window          bound the query at the API
  Tier 2  Event-name allowlist only security-relevant API calls
  Tier 3  Actor scoping        narrow to principals of interest
  Tier 4  Deduplication        collapse repeated identical calls
  Tier 5  Budgeted selection   cap tokens, keep the highest-signal events

Tiers 1-4 are deterministic and involve no model. Tier 5 is where the
judgment about "what matters most" gets applied, and it is intentionally
transparent: every dropped event is counted and reported, so the analyst
knows what was set aside rather than silently losing it.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from .account_broker import AccountBroker, AccountTarget

log = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 12  # tuned for LookupEvents rate limits; bump on the Athena path

# ----------------------------------------------------------------------
# Tier 2: event-name allowlist.
#
# Grouped by investigative purpose so a collection profile can select
# only what a given scenario needs. These are the API calls that carry
# signal in a cloud intrusion; everything else is noise for IR purposes.
# ----------------------------------------------------------------------
EVENT_GROUPS: Dict[str, Set[str]] = {
    "authentication": {
        "ConsoleLogin", "GetSessionToken", "GetFederationToken",
        "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
        "GetCallerIdentity",
    },
    "identity_mutation": {
        "CreateUser", "DeleteUser", "CreateAccessKey", "DeleteAccessKey",
        "UpdateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
        "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy",
        "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy",
        "AttachGroupPolicy", "PutGroupPolicy", "AddUserToGroup",
        "CreateRole", "DeleteRole", "UpdateAssumeRolePolicy",
        "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
        "CreateServiceLinkedRole", "PassRole",
        "DeactivateMFADevice", "DeleteVirtualMFADevice",
    },
    "discovery": {
        "ListUsers", "ListRoles", "ListPolicies", "ListAccessKeys",
        "ListAttachedUserPolicies", "ListAttachedRolePolicies",
        "GetAccountAuthorizationDetails", "ListBuckets", "DescribeInstances",
        "ListFunctions", "DescribeDBInstances", "ListSecrets",
        "GetAccountSummary", "ListGroupsForUser",
    },
    "defense_evasion": {
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
        "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount",
        "DeleteFlowLogs", "StopConfigurationRecorder",
        "DeleteConfigurationRecorder", "PutRetentionPolicy",
        "DeleteLogGroup", "DeleteLogStream", "DisableSecurityHub",
        "DeleteAlarms", "DisableAlarmActions",
    },
    "data_access": {
        "GetObject", "ListObjects", "ListObjectsV2", "CopyObject",
        "PutObject", "DeleteObject", "GetBucketAcl", "PutBucketAcl",
        "PutBucketPolicy", "GetSecretValue", "Decrypt",
        "CreateDBSnapshot", "ModifyDBSnapshotAttribute",
        "CreateSnapshot", "ModifySnapshotAttribute", "SharedSnapshotCopy",
    },
    "persistence": {
        "CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration",
        "AddPermission", "CreateEventSourceMapping", "PutRule", "PutTargets",
        "RunInstances", "CreateKeyPair", "ImportKeyPair",
        "CreateStack", "UpdateStack", "SendCommand", "StartSession",
        "CreateAccessEntry", "RegisterTaskDefinition",
    },
    "resource_exposure": {
        "AuthorizeSecurityGroupIngress", "ModifyImageAttribute",
        "ModifyDBClusterSnapshotAttribute", "PutResourcePolicy",
        "AddLayerVersionPermission", "ModifyVpcEndpointServicePermissions",
    },
}

# High-signal events. These survive budgeted selection ahead of everything
# else because in practice they are the ones that change an investigation's
# direction.
CRITICAL_EVENTS: Set[str] = (
    EVENT_GROUPS["defense_evasion"]
    | {
        "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
        "CreateUser", "AttachRolePolicy", "UpdateAssumeRolePolicy",
        "ConsoleLogin", "AssumeRole", "CreatePolicyVersion",
        "SetDefaultPolicyVersion", "PassRole", "DeactivateMFADevice",
    }
)

DEFAULT_PROFILE = [
    "authentication", "identity_mutation", "discovery",
    "defense_evasion", "data_access", "persistence", "resource_exposure",
]

# Rough chars-per-token. On purpose, conservative: better to under-fill
# the context than to blow the window on a live engagement.
CHARS_PER_TOKEN = 3.5  # TODO: measure against real tokenizer output


@dataclass
class CollectionStats:
    """Full accounting of what happened to the raw evidence.

    Every number here exists so the analyst can answer "what did the tool
    decide not to show me?" That question has to be answerable.
    """

    raw_events: int = 0
    after_event_filter: int = 0
    after_actor_filter: int = 0
    after_dedup: int = 0
    selected: int = 0
    dropped_by_budget: int = 0
    accounts_queried: int = 0
    accounts_failed: int = 0
    regions_queried: int = 0
    errors: List[str] = field(default_factory=list)
    duplicate_clusters: int = 0

    @property
    def reduction_ratio(self) -> float:
        if not self.raw_events:
            return 0.0
        return round(1 - (self.selected / self.raw_events), 4)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["reduction_ratio"] = self.reduction_ratio
        return d


@dataclass
class EvidenceBundle:
    """Filtered, budgeted evidence ready for model invocation."""

    events: List[dict] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    attack_sequences: List[dict] = field(default_factory=list)
    stats: CollectionStats = field(default_factory=CollectionStats)
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None


class EvidenceCollector:
    """Collects and reduces evidence across many accounts concurrently."""

    def __init__(
        self,
        broker: AccountBroker,
        max_workers: int = DEFAULT_MAX_WORKERS,
        event_groups: Optional[List[str]] = None,
        athena_config=None,
    ):
        self.broker = broker
        self.max_workers = max_workers
        self.allowed_events = self._build_allowlist(event_groups or DEFAULT_PROFILE)
        # When set, estate-scale collection runs as SQL instead of the
        # LookupEvents API. See services/athena_collector.py for why.
        self.athena_config = athena_config

    @staticmethod
    def _build_allowlist(groups: Iterable[str]) -> Set[str]:
        allowed: Set[str] = set()
        for g in groups:
            allowed |= EVENT_GROUPS.get(g, set())
        return allowed

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect(
        self,
        targets: List[AccountTarget],
        regions: List[str],
        window_hours: int = 72,
        end_time: Optional[datetime] = None,
        actors_of_interest: Optional[Set[str]] = None,
        token_budget: int = 40_000,
    ) -> EvidenceBundle:
        """Fan out across accounts/regions, then reduce to a token budget."""
        end = end_time or datetime.now(timezone.utc)
        start = end - timedelta(hours=window_hours)

        bundle = EvidenceBundle(window_start=start, window_end=end)
        work = [(t, r) for t in targets for r in (t.regions or regions)]
        bundle.stats.accounts_queried = len(targets)
        bundle.stats.regions_queried = len(work)

        raw_events: List[dict] = []
        findings: List[dict] = []
        sequences: List[dict] = []
        failed_accounts: Set[str] = set()

        # Estate-scale path: run Tier 1-3 reduction as SQL in Athena, then
        # fetch GuardDuty per-account in parallel. Falls through to the
        # LookupEvents path when no Athena source is configured.
        if self.athena_config is not None:
            try:
                raw_events = self._collect_via_athena(targets, regions, start, end,
                                                       actors_of_interest)
            except Exception as exc:  # noqa: BLE001
                bundle.stats.errors.append(f"Athena collection failed: {_short(exc)}")
                log.warning("Athena path failed (%s); falling back to API", _short(exc))
                raw_events = []
            findings, sequences, failed = self._gather_guardduty(targets, regions)
            failed_accounts |= failed
        else:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {
                    pool.submit(self._collect_one, t, r, start, end): (t, r)
                    for t, r in work
                }
                for fut in as_completed(futures):
                    target, region = futures[fut]
                    try:
                        ev, fi, seq = fut.result()
                        raw_events.extend(ev)
                        findings.extend(fi)
                        sequences.extend(seq)
                    except Exception as exc:  # noqa: BLE001
                        failed_accounts.add(target.account_id)
                        bundle.stats.errors.append(
                            f"{target.account_id}/{region}: {_short(exc)}"
                        )

        bundle.stats.accounts_failed = len(failed_accounts)
        bundle.stats.raw_events = len(raw_events)

        # Tier 2 already applied server-side where possible; enforce here
        # too since LookupEvents attribute filters are limited.
        filtered = [e for e in raw_events if self._event_name(e) in self.allowed_events]
        bundle.stats.after_event_filter = len(filtered)

        # Tier 3: actor scoping
        if actors_of_interest:
            filtered = [
                e for e in filtered
                if self._actor(e) and any(a in self._actor(e) for a in actors_of_interest)
            ]
        bundle.stats.after_actor_filter = len(filtered)

        # Tier 4: dedup
        filtered, clusters = self._deduplicate(filtered)
        bundle.stats.after_dedup = len(filtered)
        bundle.stats.duplicate_clusters = clusters

        # Tier 5: budgeted selection
        selected = self._apply_budget(filtered, token_budget)
        bundle.stats.selected = len(selected)
        bundle.stats.dropped_by_budget = len(filtered) - len(selected)

        bundle.events = selected
        bundle.findings = findings
        bundle.attack_sequences = sequences

        log.info(
            "Collection complete: %d raw -> %d selected (%.1f%% reduction) across %d account/regions",
            bundle.stats.raw_events, bundle.stats.selected,
            bundle.stats.reduction_ratio * 100, len(work),
        )
        return bundle

    def _collect_one(self, target, region, start, end):
        session = self.broker.session_for(target, region=region)
        events = self._lookup_cloudtrail(session, start, end, target.account_id, region)
        findings, sequences = self._fetch_guardduty(session, target.account_id, region)
        return events, findings, sequences

    def _collect_via_athena(self, targets, regions, start, end, actors):
        """Run event collection as a single SQL query across all accounts.

        Athena reads the trail's S3 data directly, so one query covers the
        whole estate. The query itself applies the time window, event
        allowlist, and actor scoping server-side; only filtered rows
        return. This is the path that makes hundred-million-event estates
        tractable.
        """
        from .athena_collector import AthenaCollector

        # Athena queries the trail bucket from wherever the bucket owner
        # grants access, typically the security tooling account, so a base
        # session is sufficient rather than per-account assumed roles.
        session = self.broker._base_session
        collector = AthenaCollector(session, self.athena_config)
        account_ids = [t.account_id for t in targets]
        events = collector.collect(
            account_ids=account_ids,
            regions=regions,
            start=start,
            end=end,
            allowed_events=self.allowed_events,
            actors_of_interest=actors,
        )
        log.info("Athena returned %d filtered events", len(events))
        return events

    def _gather_guardduty(self, targets, regions):
        """Fetch GuardDuty findings per account/region in parallel.

        Kept separate from the Athena event path because GuardDuty has no
        S3-queryable equivalent; it is always an API fetch.
        """
        findings: List[dict] = []
        sequences: List[dict] = []
        failed: Set[str] = set()
        work = [(t, r) for t in targets for r in (t.regions or regions)]

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._guardduty_for, t, r): (t, r) for t, r in work
            }
            for fut in as_completed(futures):
                target, _ = futures[fut]
                try:
                    fi, seq = fut.result()
                    findings.extend(fi)
                    sequences.extend(seq)
                except Exception:  # noqa: BLE001
                    failed.add(target.account_id)
        return findings, sequences, failed

    def _guardduty_for(self, target, region):
        session = self.broker.session_for(target, region=region)
        return self._fetch_guardduty(session, target.account_id, region)

    def _lookup_cloudtrail(self, session, start, end, account_id, region) -> List[dict]:
        """Query CloudTrail with the time window bound at the API (Tier 1).

        Note: LookupEvents permits only one attribute filter per call, so
        event-name filtering happens client-side. For estates large enough
        that this is too slow, the intended path is Athena or Security Lake
        against the trail's S3 bucket; see docs/PHASE02.md.
        """
        out: List[dict] = []
        try:
            ct = session.client("cloudtrail")
            paginator = ct.get_paginator("lookup_events")
            for page in paginator.paginate(
                StartTime=start,
                EndTime=end,
                PaginationConfig={"PageSize": 50},
            ):
                for ev in page.get("Events", []):
                    raw = ev.get("CloudTrailEvent")
                    parsed = {}
                    if raw:
                        try:
                            parsed = json.loads(raw)
                        except (json.JSONDecodeError, TypeError):
                            parsed = {}
                    name = parsed.get("eventName") or ev.get("EventName", "")
                    if name not in self.allowed_events:
                        continue
                    parsed.setdefault("eventName", name)
                    parsed["_specter_account"] = account_id
                    parsed["_specter_region"] = region
                    out.append(parsed)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"CloudTrail lookup failed: {_short(exc)}") from exc
        return out

    def _fetch_guardduty(self, session, account_id, region):
        """Pull GuardDuty findings, separating Extended Threat Detection sequences.

        Attack-sequence findings are GuardDuty's own multi-stage correlation
        with ATT&CK tactics already attached. They are pulled out separately
        because they are far higher-signal than individual findings and
        should never be dropped by budget.
        """
        findings: List[dict] = []
        sequences: List[dict] = []
        try:
            gd = session.client("guardduty")
            for det in gd.list_detectors().get("DetectorIds", []):
                ids: List[str] = []
                paginator = gd.get_paginator("list_findings")
                for page in paginator.paginate(
                    DetectorId=det,
                    FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
                ):
                    ids.extend(page.get("FindingIds", []))
                for i in range(0, len(ids), 50):
                    batch = gd.get_findings(DetectorId=det, FindingIds=ids[i : i + 50])
                    for f in batch.get("Findings", []):
                        f["_specter_account"] = account_id
                        f["_specter_region"] = region
                        if "AttackSequence" in f.get("Type", "") or f.get(
                            "Service", {}
                        ).get("Detection", {}).get("Sequence"):
                            sequences.append(f)
                        else:
                            findings.append(f)
        except Exception as exc:  # noqa: BLE001
            log.warning("GuardDuty fetch failed for %s/%s: %s", account_id, region, exc)
        return findings, sequences

    # ------------------------------------------------------------------
    # Reduction
    # ------------------------------------------------------------------

    @staticmethod
    def _event_name(event: dict) -> str:
        return event.get("eventName", "")

    @staticmethod
    def _actor(event: dict) -> str:
        ident = event.get("userIdentity", {}) or {}
        return (
            ident.get("arn")
            or ident.get("userName")
            or ident.get("principalId")
            or ""
        )

    def _deduplicate(self, events: List[dict]):
        """Collapse identical repeated calls, keeping first and last occurrence.

        Automation produces enormous runs of the same call. Keeping the
        boundaries of each run preserves the timeline shape while removing
        the bulk. A _specter_repeat_count is attached so nothing about
        volume is hidden from the model.
        """
        clusters: Dict[tuple, List[dict]] = defaultdict(list)
        for ev in events:
            key = (
                self._event_name(ev),
                self._actor(ev),
                ev.get("sourceIPAddress", ""),
                ev.get("_specter_account", ""),
                ev.get("_specter_region", ""),
            )
            clusters[key].append(ev)

        out: List[dict] = []
        collapsed = 0
        for key, group in clusters.items():
            if len(group) <= 2:
                out.extend(group)
                continue
            collapsed += 1
            group.sort(key=lambda e: e.get("eventTime", ""))
            first, last = group[0], group[-1]
            first["_specter_repeat_count"] = len(group)
            first["_specter_repeat_window"] = [
                first.get("eventTime"), last.get("eventTime")
            ]
            out.append(first)
            out.append(last)
        return out, collapsed

    def _apply_budget(self, events: List[dict], token_budget: int) -> List[dict]:
        """Select the highest-signal events that fit the token budget.

        Ordering: critical events first, then defense-evasion-adjacent,
        then chronological. Within the budget the timeline is restored to
        chronological order so the model sees a coherent narrative.
        """
        if not events:
            return []

        def signal_rank(ev: dict) -> int:
            name = self._event_name(ev)
            if name in CRITICAL_EVENTS:
                return 0
            if name in EVENT_GROUPS["identity_mutation"]:
                return 1
            if name in EVENT_GROUPS["data_access"]:
                return 2
            if name in EVENT_GROUPS["persistence"]:
                return 3
            return 4

        ranked = sorted(events, key=lambda e: (signal_rank(e), e.get("eventTime", "")))

        budget_chars = int(token_budget * CHARS_PER_TOKEN)
        selected: List[dict] = []
        used = 0
        for ev in ranked:
            slim = self._slim(ev)
            cost = len(json.dumps(slim))
            if used + cost > budget_chars:
                continue
            selected.append(slim)
            used += cost

        selected.sort(key=lambda e: e.get("eventTime", ""))
        return selected

    @staticmethod
    def _slim(event: dict) -> dict:
        """Strip CloudTrail records to investigative essentials.

        Full records carry large response payloads that consume budget
        without adding investigative value. This typically cuts per-event
        size by more than half.
        """
        ident = event.get("userIdentity", {}) or {}
        slim = {
            "eventTime": event.get("eventTime"),
            "eventName": event.get("eventName"),
            "eventSource": event.get("eventSource"),
            "awsRegion": event.get("awsRegion") or event.get("_specter_region"),
            "sourceIPAddress": event.get("sourceIPAddress"),
            "userAgent": _truncate(event.get("userAgent"), 80),
            "account": event.get("_specter_account") or event.get("recipientAccountId"),
            "actor": {
                "type": ident.get("type"),
                "arn": ident.get("arn"),
                "userName": ident.get("userName"),
            },
        }
        # session key lets us chain AssumeRole -> later actions
        if ident.get("accessKeyId"):
            slim["accessKeyId"] = ident["accessKeyId"]
        # keep minted key id from AssumeRole responses (id only, never the secret)
        resp = event.get("responseElements") or {}
        if isinstance(resp, dict) and isinstance(resp.get("credentials"), dict):
            kid = resp["credentials"].get("accessKeyId")
            if kid:
                slim["responseElements"] = {"credentials": {"accessKeyId": kid}}
        if event.get("errorCode"):
            slim["errorCode"] = event["errorCode"]
        if event.get("requestParameters"):
            slim["requestParameters"] = _prune(event["requestParameters"])
        if event.get("_specter_repeat_count"):
            slim["repeatCount"] = event["_specter_repeat_count"]
            slim["repeatWindow"] = event.get("_specter_repeat_window")
        mfa = (ident.get("sessionContext", {}) or {}).get("attributes", {}) or {}
        if "mfaAuthenticated" in mfa:
            slim["mfaAuthenticated"] = mfa["mfaAuthenticated"]
        return {k: v for k, v in slim.items() if v is not None}


def _prune(obj: Any, max_len: int = 260) -> Any:
    """Shrink nested request parameters to keep budget under control."""
    try:
        text = json.dumps(obj)
    except (TypeError, ValueError):
        return str(obj)[:max_len]
    if len(text) <= max_len:
        return obj
    if isinstance(obj, dict):
        return {k: _truncate(str(v), 60) for k, v in list(obj.items())[:8]}
    return text[:max_len]


def _truncate(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _short(exc: Exception, limit: int = 140) -> str:
    text = str(exc)
    return text if len(text) <= limit else text[: limit - 3] + "..."
