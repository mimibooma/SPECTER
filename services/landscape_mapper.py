"""
Evidence Landscape Mapper (Phase 02 core deliverable).

Before an investigation plan is worth anything, you have to know what
evidence actually exists. This module answers that question across many
accounts at once and produces a forensic readiness assessment.

The output is on purpose blunt about gaps. A plan built on the
assumption of complete telemetry is worse than useless in a real
engagement, because it sends an analyst looking for evidence that was
never being recorded. Absent evidence is a finding.

Concurrency model: one worker per (account, region) pair, bounded by a
thread pool. Each worker builds its own clients from its own session.
Failures are captured per-target and never abort the sweep.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .account_broker import AccountBroker, AccountTarget

log = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 12


@dataclass
class TrailFinding:
    name: str
    is_multi_region: bool
    is_logging: bool
    has_log_file_validation: bool
    s3_bucket: Optional[str]
    is_organization_trail: bool = False
    data_events_configured: bool = False


@dataclass
class RegionLandscape:
    """What evidence exists in one account/region."""

    account_id: str
    region: str
    reachable: bool = True
    error: Optional[str] = None

    cloudtrail_trails: List[TrailFinding] = field(default_factory=list)
    guardduty_enabled: bool = False
    guardduty_detector_ids: List[str] = field(default_factory=list)
    config_recording: bool = False
    vpc_flow_logs_count: int = 0
    securityhub_enabled: bool = False

    readiness_score: float = 0.0
    readiness_band: str = "unknown"
    gaps: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cloudtrail_trails"] = [asdict(t) for t in self.cloudtrail_trails]
        return d


# ----------------------------------------------------------------------
# Readiness scoring
#
# Weights reflect what actually determines whether a cloud investigation
# can be completed, not what is easy to measure. Management-event
# CloudTrail is weighted highest because without it there is effectively
# no investigation at all. Everything else degrades the picture rather
# than ending it.
# ----------------------------------------------------------------------
READINESS_WEIGHTS = {
    "cloudtrail_active": 35,
    "cloudtrail_multiregion": 10,
    "cloudtrail_validation": 5,
    "cloudtrail_data_events": 10,
    "guardduty": 20,
    "config": 8,
    "flow_logs": 7,
    "securityhub": 5,
}


class LandscapeMapper:
    """Maps available forensic evidence across accounts and regions."""

    def __init__(self, broker: AccountBroker, max_workers: int = DEFAULT_MAX_WORKERS):
        self.broker = broker
        self.max_workers = max_workers

    def map_estate(
        self,
        targets: List[AccountTarget],
        regions: List[str],
    ) -> Dict[str, List[RegionLandscape]]:
        """Sweep every (account, region) pair concurrently.

        Returns a dict keyed by account_id. Unreachable accounts appear
        with reachable=False rather than being silently dropped, because
        "we could not see this account" is itself something the analyst
        and the model both need to know.
        """
        work = [(t, r) for t in targets for r in (t.regions or regions)]
        results: Dict[str, List[RegionLandscape]] = {t.account_id: [] for t in targets}

        log.info(
            "Mapping %d account/region pairs across %d accounts (max_workers=%d)",
            len(work), len(targets), self.max_workers,
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._map_one, target, region): (target, region)
                for target, region in work
            }
            for fut in as_completed(futures):
                target, region = futures[fut]
                try:
                    landscape = fut.result()
                except Exception as exc:  # noqa: BLE001
                    landscape = RegionLandscape(
                        account_id=target.account_id,
                        region=region,
                        reachable=False,
                        error=str(exc),
                    )
                results[target.account_id].append(landscape)

        for account_id in results:
            results[account_id].sort(key=lambda x: x.region)
        return results

    # ------------------------------------------------------------------

    def _map_one(self, target: AccountTarget, region: str) -> RegionLandscape:
        landscape = RegionLandscape(account_id=target.account_id, region=region)

        try:
            session = self.broker.session_for(target, region=region)
        except Exception as exc:  # noqa: BLE001
            landscape.reachable = False
            landscape.error = str(exc)
            landscape.gaps.append("Account unreachable: no assumed-role access")
            self._score(landscape)
            return landscape

        self._probe_cloudtrail(session, landscape)
        self._probe_guardduty(session, landscape)
        self._probe_config(session, landscape)
        self._probe_flow_logs(session, landscape)
        self._probe_securityhub(session, landscape)
        self._score(landscape)
        return landscape

    def _probe_cloudtrail(self, session, landscape: RegionLandscape) -> None:
        try:
            ct = session.client("cloudtrail")
            # includeShadowTrails=True is load-bearing: without it a multi-region
            # trail homed in us-east-1 is invisible from us-west-2 and that region
            # scores as "no CloudTrail" when it is actually covered
            for trail in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
                name = trail.get("Name", "")
                try:
                    status = ct.get_trail_status(Name=trail.get("TrailARN", name))
                    is_logging = bool(status.get("IsLogging", False))
                except Exception:  # noqa: BLE001
                    is_logging = False

                data_events = False
                try:
                    selectors = ct.get_event_selectors(TrailName=trail.get("TrailARN", name))
                    for sel in selectors.get("EventSelectors", []):
                        if sel.get("DataResources"):
                            data_events = True
                    if selectors.get("AdvancedEventSelectors"):
                        data_events = True
                except Exception:  # noqa: BLE001
                    pass

                landscape.cloudtrail_trails.append(
                    TrailFinding(
                        name=name,
                        is_multi_region=bool(trail.get("IsMultiRegionTrail", False)),
                        is_logging=is_logging,
                        has_log_file_validation=bool(trail.get("LogFileValidationEnabled", False)),
                        s3_bucket=trail.get("S3BucketName"),
                        is_organization_trail=bool(trail.get("IsOrganizationTrail", False)),
                        data_events_configured=data_events,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            landscape.gaps.append(f"CloudTrail not enumerable: {_short(exc)}")

    def _probe_guardduty(self, session, landscape: RegionLandscape) -> None:
        try:
            gd = session.client("guardduty")
            detectors = gd.list_detectors().get("DetectorIds", [])
            landscape.guardduty_detector_ids = detectors
            for det in detectors:
                try:
                    if gd.get_detector(DetectorId=det).get("Status") == "ENABLED":
                        landscape.guardduty_enabled = True
                except Exception:  # noqa: BLE001
                    continue
        except Exception as exc:  # noqa: BLE001
            landscape.gaps.append(f"GuardDuty not enumerable: {_short(exc)}")

    def _probe_config(self, session, landscape: RegionLandscape) -> None:
        try:
            cfg = session.client("config")
            for rec in cfg.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            ):
                if rec.get("recording"):
                    landscape.config_recording = True
        except Exception:  # noqa: BLE001
            pass

    def _probe_flow_logs(self, session, landscape: RegionLandscape) -> None:
        try:
            ec2 = session.client("ec2")
            paginator = ec2.get_paginator("describe_flow_logs")
            count = 0
            for page in paginator.paginate():
                count += len(page.get("FlowLogs", []))
            landscape.vpc_flow_logs_count = count
        except Exception:  # noqa: BLE001
            pass

    def _probe_securityhub(self, session, landscape: RegionLandscape) -> None:
        try:
            sh = session.client("securityhub")
            sh.describe_hub()
            landscape.securityhub_enabled = True
        except Exception:  # noqa: BLE001
            landscape.securityhub_enabled = False

    # ------------------------------------------------------------------

    def _score(self, landscape: RegionLandscape) -> None:
        """Compute readiness 0-100 and record human-readable gaps."""
        if not landscape.reachable:
            landscape.readiness_score = 0.0
            landscape.readiness_band = "no_access"
            return

        score = 0
        trails = landscape.cloudtrail_trails
        active = [t for t in trails if t.is_logging]

        if active:
            score += READINESS_WEIGHTS["cloudtrail_active"]
            landscape.strengths.append(f"{len(active)} active CloudTrail trail(s)")
            if any(t.is_multi_region for t in active):
                score += READINESS_WEIGHTS["cloudtrail_multiregion"]
            else:
                landscape.gaps.append(
                    "No multi-region CloudTrail: activity in unmonitored regions is invisible"
                )
            if any(t.has_log_file_validation for t in active):
                score += READINESS_WEIGHTS["cloudtrail_validation"]
            else:
                landscape.gaps.append(
                    "Log file validation off: log integrity cannot be proven for evidentiary use"
                )
            if any(t.data_events_configured for t in active):
                score += READINESS_WEIGHTS["cloudtrail_data_events"]
            else:
                landscape.gaps.append(
                    "No S3/Lambda data events: object-level access and exfiltration are not recorded"
                )
        else:
            landscape.gaps.append(
                "CRITICAL: no active CloudTrail trail. Control-plane activity is not being recorded."
            )
            if trails:
                landscape.gaps.append(
                    f"{len(trails)} trail(s) exist but are not logging: check for deliberate StopLogging"
                )

        if landscape.guardduty_enabled:
            score += READINESS_WEIGHTS["guardduty"]
            landscape.strengths.append("GuardDuty enabled")
        else:
            landscape.gaps.append(
                "GuardDuty disabled: no managed threat detection or attack-sequence correlation"
            )

        if landscape.config_recording:
            score += READINESS_WEIGHTS["config"]
            landscape.strengths.append("AWS Config recording")
        else:
            landscape.gaps.append(
                "AWS Config not recording: resource configuration history unavailable for timeline reconstruction"
            )

        if landscape.vpc_flow_logs_count > 0:
            score += READINESS_WEIGHTS["flow_logs"]
            landscape.strengths.append(f"{landscape.vpc_flow_logs_count} VPC flow log(s)")
        else:
            landscape.gaps.append(
                "No VPC flow logs: lateral movement and exfiltration volume cannot be corroborated"
            )

        if landscape.securityhub_enabled:
            score += READINESS_WEIGHTS["securityhub"]

        landscape.readiness_score = float(score)
        landscape.readiness_band = _band(score)


def _band(score: float) -> str:
    if score >= 80:
        return "strong"
    if score >= 60:
        return "adequate"
    if score >= 35:
        return "degraded"
    return "severely_limited"


def _short(exc: Exception, limit: int = 120) -> str:
    text = str(exc)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def summarize_estate(estate: Dict[str, List[RegionLandscape]]) -> dict:
    """Condense a full estate map into something small enough to prompt with.

    This is the hand-off point between collection and reasoning. The model
    never sees the raw sweep; it sees this.
    """
    total = 0
    reachable = 0
    no_ct = []
    no_gd = []
    scores = []
    all_gaps: Dict[str, int] = {}

    for account_id, regions in estate.items():
        for r in regions:
            total += 1
            if not r.reachable:
                continue
            reachable += 1
            scores.append(r.readiness_score)
            if not any(t.is_logging for t in r.cloudtrail_trails):
                no_ct.append(f"{account_id}/{r.region}")
            if not r.guardduty_enabled:
                no_gd.append(f"{account_id}/{r.region}")
            for gap in r.gaps:
                key = gap.split(":")[0]
                all_gaps[key] = all_gaps.get(key, 0) + 1

    return {
        "accounts_examined": len(estate),
        "account_regions_examined": total,
        "account_regions_reachable": reachable,
        "account_regions_unreachable": total - reachable,
        "mean_readiness_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "regions_without_active_cloudtrail": no_ct,
        "regions_without_guardduty": no_gd,
        "gap_frequency": dict(sorted(all_gaps.items(), key=lambda kv: -kv[1])),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
