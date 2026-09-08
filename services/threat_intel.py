"""
IOC extraction and threat intelligence enrichment.

Two responsibilities:
  1. Pull indicators out of CloudTrail events and GuardDuty findings.
  2. Enrich them against feeds, degrading gracefully when feeds are absent.

Feed abstraction is deliberate. Mock file-backed feeds let development
proceed without API credentials, and the same interface accepts a real
provider later without touching callers.

Threat groups resolve to ATT&CK G-IDs via scoring_engine.resolve_threat_group
so that "APT29" and "Cozy Bear" enrich identically.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from .scoring_engine import THREAT_GROUPS

log = logging.getLogger(__name__)

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|top|xyz|club|online|site|tk|ml|ga|cf|gq|su|pw)\b"
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Noise domains that appear constantly in AWS telemetry and are never IOCs.
DOMAIN_DENYLIST = {
    "amazonaws.com", "aws.amazon.com", "console.aws.amazon.com",
    "signin.aws.amazon.com", "s3.amazonaws.com", "cloudfront.net",
    "amazon.com", "microsoft.com", "windows.net", "google.com",
}


@dataclass
class IOC:
    value: str
    ioc_type: str  # ip | domain | md5 | sha256
    source: str
    context: str = ""

    def key(self) -> str:
        return f"{self.ioc_type}:{self.value.lower()}"


@dataclass
class Enrichment:
    ioc: IOC
    malicious: bool = False
    confidence: int = 0
    threat_groups: List[str] = field(default_factory=list)  # ATT&CK G-IDs
    threat_group_names: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    feeds_matched: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ioc"] = asdict(self.ioc)
        return d


class ThreatFeed(ABC):
    """Interface every feed implements. Real providers slot in here."""

    name: str = "unnamed"

    @abstractmethod
    def lookup(self, ioc: IOC) -> Optional[Enrichment]:
        ...

    @property
    def available(self) -> bool:
        return True


class FileFeed(ThreatFeed):
    """File-backed feed.

    Accepts pipe- or comma-delimited lines. Pipe is preferred because
    threat descriptions frequently contain commas:

        <indicator>|<category>|<confidence>|<severity>|<first>|<last>|<description>

    Threat group attribution is recovered from the category and the free-text
    description, since feeds in the wild rarely carry a dedicated group column.
    Lines beginning with # are comments.
    """

    def __init__(self, path: str, name: str, ioc_type: str):
        self.path = Path(path)
        self.name = name
        self.ioc_type = ioc_type
        self._entries: Dict[str, dict] = {}
        self._loaded = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            log.info("Feed %s absent at %s; enrichment will degrade gracefully",
                     self.name, self.path)
            return
        try:
            for line in self.path.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                delimiter = "|" if "|" in line else ","
                parts = [p.strip() for p in line.split(delimiter)]
                indicator = parts[0].lower()
                if not indicator or " " in indicator:
                    continue

                category = parts[1] if len(parts) > 1 and parts[1] else "suspicious"
                confidence = _safe_int(parts[2], 75) if len(parts) > 2 else 75
                description = parts[6] if len(parts) > 6 else ""

                # Recover attribution from category and description text.
                group = None
                haystack = f"{category} {description}"
                for alias, gid in _ALIAS_INDEX_REF().items():
                    if alias in haystack.lower():
                        group = gid
                        break

                self._entries[indicator] = {
                    "confidence": confidence,
                    "group": group,
                    "category": category,
                    "description": description,
                }
            self._loaded = bool(self._entries)
            log.info("Loaded %d indicators from %s", len(self._entries), self.name)
        except OSError as exc:
            log.warning("Could not read feed %s: %s", self.name, exc)

    @property
    def available(self) -> bool:
        return self._loaded and bool(self._entries)

    def lookup(self, ioc: IOC) -> Optional[Enrichment]:
        if ioc.ioc_type != self.ioc_type:
            return None
        entry = self._entries.get(ioc.value.lower())
        if not entry:
            return None

        # Group is already a resolved ATT&CK G-ID from _load()
        gid = entry.get("group")
        return Enrichment(
            ioc=ioc,
            malicious=True,
            confidence=entry["confidence"],
            threat_groups=[gid] if gid else [],
            threat_group_names=[THREAT_GROUPS[gid]["name"]] if gid else [],
            categories=[entry["category"]],
            feeds_matched=[self.name],
        )


class IOCExtractor:
    """Pulls indicators from cloud telemetry."""

    def extract_from_events(self, events: Iterable[dict]) -> List[IOC]:
        out: Dict[str, IOC] = {}
        for ev in events:
            src = ev.get("sourceIPAddress")
            if src and self._is_routable_ip(src):
                ioc = IOC(src, "ip", "cloudtrail",
                          f"{ev.get('eventName', '?')} by {_actor(ev)}")
                out.setdefault(ioc.key(), ioc)
            # Domain-shaped source addresses appear for AWS service principals
            if src and not IPV4_RE.fullmatch(src or ""):
                for dom in self._domains(src):
                    ioc = IOC(dom, "domain", "cloudtrail", "sourceIPAddress")
                    out.setdefault(ioc.key(), ioc)
        return list(out.values())

    def extract_from_findings(self, findings: Iterable[dict]) -> List[IOC]:
        out: Dict[str, IOC] = {}
        for f in findings:
            blob = " ".join(
                str(f.get(k, "")) for k in ("Title", "Description", "Type")
            )
            service = f.get("Service", {}) or {}
            action = service.get("Action", {}) or {}
            blob += " " + str(action)

            for ip in IPV4_RE.findall(blob):
                if self._is_routable_ip(ip):
                    ioc = IOC(ip, "ip", "guardduty", f.get("Type", ""))
                    out.setdefault(ioc.key(), ioc)
            for dom in self._domains(blob):
                ioc = IOC(dom, "domain", "guardduty", f.get("Type", ""))
                out.setdefault(ioc.key(), ioc)
            for h in SHA256_RE.findall(blob):
                ioc = IOC(h, "sha256", "guardduty", f.get("Type", ""))
                out.setdefault(ioc.key(), ioc)
            for h in MD5_RE.findall(blob):
                if not SHA256_RE.fullmatch(h):
                    ioc = IOC(h, "md5", "guardduty", f.get("Type", ""))
                    out.setdefault(ioc.key(), ioc)
        return list(out.values())

    @staticmethod
    def _domains(text: str) -> Set[str]:
        found = set()
        for match in DOMAIN_RE.findall(text or ""):
            lowered = match.lower().rstrip(".")
            if any(lowered == d or lowered.endswith("." + d) for d in DOMAIN_DENYLIST):
                continue
            found.add(lowered)
        return found

    @staticmethod
    def _is_routable_ip(value: str) -> bool:
        """Filter private, loopback, and link-local addresses.

        Internal RFC1918 addresses are not threat indicators and enriching
        them wastes lookups and produces misleading matches.
        """
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved)


class ThreatIntelService:
    """Coordinates extraction and enrichment across feeds."""

    def __init__(self, feed_dir: str = "mock_feeds"):
        base = Path(feed_dir)
        self.extractor = IOCExtractor()
        self.feeds: List[ThreatFeed] = [
            FileFeed(str(base / "malicious_ips.txt"), "mock_ip_feed", "ip"),
            FileFeed(str(base / "malicious_domains.txt"), "mock_domain_feed", "domain"),
            FileFeed(str(base / "malicious_hashes.txt"), "mock_hash_feed", "sha256"),
        ]
        self.degraded = not any(f.available for f in self.feeds)
        if self.degraded:
            log.warning(
                "No threat feeds loaded. Enrichment disabled; scoring will "
                "rely on business context and evidence quality only."
            )

    def enrich(self, iocs: List[IOC]) -> Dict[str, Enrichment]:
        results: Dict[str, Enrichment] = {}
        for ioc in iocs:
            merged: Optional[Enrichment] = None
            for feed in self.feeds:
                if not feed.available:
                    continue
                hit = feed.lookup(ioc)
                if not hit:
                    continue
                if merged is None:
                    merged = hit
                else:
                    merged.confidence = max(merged.confidence, hit.confidence)
                    merged.feeds_matched.extend(hit.feeds_matched)
                    merged.threat_groups = list(set(merged.threat_groups + hit.threat_groups))
                    merged.threat_group_names = list(
                        set(merged.threat_group_names + hit.threat_group_names)
                    )
                    merged.categories = list(set(merged.categories + hit.categories))
            if merged:
                results[ioc.key()] = merged
        return results

    def analyze(self, events: List[dict], findings: List[dict]) -> dict:
        """Full pass: extract, enrich, and summarize for prompt inclusion."""
        iocs = self.extractor.extract_from_events(events)
        iocs += self.extractor.extract_from_findings(findings)

        deduped: Dict[str, IOC] = {i.key(): i for i in iocs}
        enrichments = self.enrich(list(deduped.values()))

        groups: Set[str] = set()
        for e in enrichments.values():
            groups.update(e.threat_group_names)

        return {
            "iocs_extracted": len(deduped),
            "iocs_enriched": len(enrichments),
            "malicious_iocs": [
                {
                    "value": e.ioc.value,
                    "type": e.ioc.ioc_type,
                    "confidence": e.confidence,
                    "threat_groups": e.threat_group_names,
                    "attack_group_ids": e.threat_groups,
                    "categories": e.categories,
                    "context": e.ioc.context,
                }
                for e in enrichments.values()
            ],
            "attributed_groups": sorted(groups),
            "enrichment_degraded": self.degraded,
        }


def _ALIAS_INDEX_REF() -> Dict[str, str]:
    """Lowercase alias -> ATT&CK group ID, for free-text attribution recovery.

    Built once from the canonical table in scoring_engine so there is a
    single source of truth for group identity across the codebase.
    """
    global _ALIAS_CACHE
    if _ALIAS_CACHE is None:
        _ALIAS_CACHE = {
            alias.lower(): gid
            for gid, meta in THREAT_GROUPS.items()
            for alias in meta["aliases"]
        }
    return _ALIAS_CACHE


_ALIAS_CACHE: Optional[Dict[str, str]] = None


def _actor(event: dict) -> str:
    ident = event.get("actor") or event.get("userIdentity") or {}
    return ident.get("arn") or ident.get("userName") or "unknown"


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
