"""
Multi-dimensional investigation step prioritization.

Layered on top of MITRE ATT&CK rather than replacing it. Every step keeps
its technique ID and tactic; this adds the "which of these ATT&CK-mapped
steps should an analyst do first" judgment that ATT&CK on purpose does
not make.

Four dimensions, weighted:

  Business impact    40%   what does this asset mean to the organization
  Threat confidence  30%   how sure are we this is real
  Response effort    20%   how expensive is it to act (inverted)
  Evidence quality   10%   how much do we trust what we are looking at

FIXES APPLIED relative to the prior draft (see docs/PHASE02.md):
  - Composite score no longer divided by 10 after weighting, which had
    collapsed every result into the "low" band and made the thresholds
    unreachable.
  - Evidence quality no longer sums three 0-10 values into a 0-30 range
    before clamping, which had pinned nearly everything at 10.
  - Critical-path sort order corrected: overdue items now surface first.
  - Response effort no longer increases when analysts are added.
  - Threat group matching uses ATT&CK G-IDs with alias resolution instead
    of five hardcoded names, so APT29 and Cozy Bear resolve identically.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

log = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    "business_impact": 0.40,
    "threat_confidence": 0.30,
    "response_effort": 0.20,
    "evidence_quality": 0.10,
}

DEFAULT_THRESHOLDS = {"critical": 7.5, "high": 5.0, "medium": 2.5, "low": 0.0}
# NOTE: thresholds came from tuning on synthetic data; revisit once there
# are real incidents to calibrate against

# ATT&CK group IDs with common aliases. Group IDs use a G prefix; technique
# IDs use T. Conflating them (as "threat_actor": "T1234" did) is a real
# correctness problem because it makes output non-joinable against ATT&CK.
THREAT_GROUPS: Dict[str, Dict[str, Any]] = {
    "G0016": {"name": "APT29", "aliases": ["APT29", "Cozy Bear", "Midnight Blizzard",
                                           "Nobelium", "The Dukes", "UNC2452"], "tier": "state"},
    "G0007": {"name": "APT28", "aliases": ["APT28", "Fancy Bear", "Forest Blizzard",
                                           "Sofacy", "Sednit", "STRONTIUM"], "tier": "state"},
    "G0032": {"name": "Lazarus Group", "aliases": ["Lazarus", "Lazarus Group",
                                                   "Hidden Cobra", "Diamond Sleet",
                                                   "ZINC"], "tier": "state"},
    "G0065": {"name": "Leviathan", "aliases": ["APT40", "Leviathan", "Gingham Typhoon",
                                               "TEMP.Periscope"], "tier": "state"},
    "G0010": {"name": "Turla", "aliases": ["Turla", "Secret Blizzard", "Venomous Bear",
                                           "Waterbug"], "tier": "state"},
    "G0139": {"name": "TeamTNT", "aliases": ["TeamTNT"], "tier": "criminal"},
    "G0122": {"name": "Silent Librarian", "aliases": ["Silent Librarian",
                                                      "COBALT DICKENS"], "tier": "criminal"},
    "G1015": {"name": "Scattered Spider", "aliases": ["Scattered Spider", "Octo Tempest",
                                                      "UNC3944", "Muddled Libra"],
              "tier": "criminal"},
    "G0102": {"name": "Wizard Spider", "aliases": ["Wizard Spider", "TrickBot Group",
                                                   "UNC1878"], "tier": "criminal"},
}

# Confidence weight by actor sophistication. A confirmed state-nexus actor
# is a stronger signal than an opportunistic cryptominer, and the score
# should say so.
TIER_BONUS = {"state": 2.0, "criminal": 1.5, "unknown": 0.5}

_ALIAS_INDEX: Dict[str, str] = {}
for _gid, _meta in THREAT_GROUPS.items():
    for _alias in _meta["aliases"]:
        _ALIAS_INDEX[_alias.lower()] = _gid


def resolve_threat_group(name: str) -> Optional[str]:
    """Map any known alias to its canonical ATT&CK group ID."""
    if not name:
        return None
    candidate = name.strip()
    if candidate.upper() in THREAT_GROUPS:
        return candidate.upper()
    return _ALIAS_INDEX.get(candidate.lower())


class ScoringEngine:
    """Computes composite priority for ATT&CK-mapped investigation steps."""

    def __init__(self, context_path: Optional[str] = None):
        self.context: Dict[str, Any] = {}
        self.assets: Dict[str, Any] = {}
        self.weights = dict(DEFAULT_WEIGHTS)
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        self.response_effort_map: Dict[str, int] = {}
        self.provider_multipliers = {"aws": 1.0, "azure": 1.2, "gcp": 1.2, "multi_cloud": 1.5}
        if context_path:
            self.load_context(context_path)

    def load_context(self, context_path: str) -> None:
        path = Path(context_path)
        if not path.exists():
            log.warning("Business context not found at %s; using defaults", context_path)
            return
        with path.open("r") as fh:
            self.context = yaml.safe_load(fh) or {}
        self.assets = self.context.get("assets", {}) or self.context.get("business_units", {}) or {}
        self.weights = {**DEFAULT_WEIGHTS, **(self.context.get("scoring_weights") or {})}
        self.thresholds = {**DEFAULT_THRESHOLDS, **(self.context.get("priority_thresholds") or {})}
        self.response_effort_map = self.context.get("response_effort_map") or {}
        self.provider_multipliers = {
            **self.provider_multipliers,
            **(self.context.get("cloud_provider_multipliers") or {}),
        }

    # ------------------------------------------------------------------
    # Dimensions
    # ------------------------------------------------------------------

    def business_impact(self, criticality: Dict[str, Any]) -> float:
        """0-10. Asset tier and blast radius dominate; sensitivity modulates."""
        tier_scores = {1: 10.0, 2: 8.0, 3: 5.0, 4: 2.0}
        tier = tier_scores.get(criticality.get("criticality_tier", 3), 5.0)

        impact_scores = {"severe": 10.0, "high": 8.0, "moderate": 5.0, "low": 2.0}
        impact = impact_scores.get(criticality.get("impact_if_compromised", "moderate"), 5.0)

        sensitivity_scores = {
            "pci": 10.0, "phi": 10.0, "phii": 10.0,
            "customer": 7.5, "internal": 5.0, "public": 1.0,
        }
        sensitivity = sensitivity_scores.get(
            str(criticality.get("data_sensitivity", "internal")).lower(), 5.0
        )

        sla = 10.0 if criticality.get("sla_breach_risk") else 0.0

        score = tier * 0.40 + impact * 0.35 + sensitivity * 0.15 + sla * 0.10
        return round(_clamp(score), 2)

    def threat_confidence(self, enrichment: Dict[str, Any]) -> float:
        """0-10. Feed confidence, corroborating IOCs, and actor attribution."""
        raw = enrichment.get("confidence")
        base = (float(raw) / 100.0) * 10.0 if raw is not None else 5.0

        actor_bonus = 0.0
        for group in enrichment.get("associated_threat_groups", []) or []:
            gid = resolve_threat_group(str(group))
            if gid:
                tier = THREAT_GROUPS[gid]["tier"]
                actor_bonus = max(actor_bonus, TIER_BONUS.get(tier, 0.5))

        iocs = enrichment.get("linked_iocs", []) or []
        ioc_bonus = min(2.0, max(0, len(iocs) - 1) * 0.5)

        sources = enrichment.get("data_sources", []) or []
        corroboration = min(1.0, max(0, len(sources) - 1) * 0.5)

        return round(_clamp(base + actor_bonus + ioc_bonus + corroboration), 2)

    def evidence_quality(self, quality: Dict[str, Any]) -> float:
        """0-10. Mean of completeness/reliability/confidence, penalized for gaps.

        Averaged rather than summed. The prior implementation added three
        0-10 values and clamped at 10, which meant any input above ~33%
        across the board produced a perfect score.
        """
        completeness = float(quality.get("completeness", 50)) / 10.0
        reliability = float(quality.get("reliability", 50)) / 10.0
        confidence = float(quality.get("confidence", 50)) / 10.0
        base = (completeness + reliability + confidence) / 3.0

        blind_spots = quality.get("blind_spots", []) or []
        gaps = quality.get("evidence_gaps", {}) or {}
        penalty = len(blind_spots) * 1.0 + len(gaps) * 0.5

        return round(_clamp(base - penalty), 2)

    def response_effort(self, level: int, analysts: int = 1) -> float:
        """1-10 raw effort. Higher means more expensive to act.

        Additional analysts reduce effort with diminishing returns. The
        prior version increased effort as analysts were added.
        """
        base = {1: 1.0, 2: 3.0, 3: 5.0, 4: 7.5, 5: 10.0}.get(int(level or 3), 5.0)
        if analysts > 1:
            base = base / (1 + 0.35 * (analysts - 1))
        return round(_clamp(base, lo=1.0), 2)

    def estimate_effort_level(self, action: str, provider: str = "aws") -> int:
        """Map an action string to a 1-5 effort level using configured hints."""
        key = (action or "").lower()
        level = 3
        for phrase, val in (self.response_effort_map or {}).items():
            if str(phrase).lower() in key:
                level = int(val)
                break
        adjusted = level * self.provider_multipliers.get(provider, 1.0)
        return int(max(1, min(5, round(adjusted))))

    # ------------------------------------------------------------------
    # Composite
    # ------------------------------------------------------------------

    def composite_score(self, step: Dict[str, Any]) -> float:
        """Weighted 0-10 composite. Weights sum to 1.0, so the result stays 0-10."""
        bi = self.business_impact(step.get("business_criticality", {}) or {})
        tc = self.threat_confidence(step.get("threat_intel_enrichment", {}) or {})
        eq = self.evidence_quality(step.get("evidence_quality", {}) or {})

        effort_level = step.get("response_effort", 3)
        analysts = step.get("assigned_analysts", 1)
        effort = self.response_effort(effort_level, analysts)
        effort_component = 10.0 - effort  # cheap actions score higher

        score = (
            bi * self.weights["business_impact"]
            + tc * self.weights["threat_confidence"]
            + effort_component * self.weights["response_effort"]
            + eq * self.weights["evidence_quality"]
        )

        step["_dimension_scores"] = {
            "business_impact": bi,
            "threat_confidence": tc,
            "response_effort_raw": effort,
            "response_effort_component": round(effort_component, 2),
            "evidence_quality": eq,
        }
        return round(_clamp(score), 2)

    def map_priority(self, score: float) -> str:
        if score >= self.thresholds["critical"]:
            return "critical"
        if score >= self.thresholds["high"]:
            return "high"
        if score >= self.thresholds["medium"]:
            return "medium"
        return "low"

    def is_overdue(self, step: Dict[str, Any]) -> bool:
        ts = step.get("time_sensitivity", {}) or {}
        if "overdue" in ts:
            return bool(ts["overdue"])
        age = ts.get("incident_age_hours")
        window = ts.get("optimal_response_window_hours")
        if age is None or window is None:
            return False
        return float(age) > float(window)

    def score_steps(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score, annotate, and order steps by priority.

        Sort: composite descending, overdue first within ties, then the
        more critical asset tier.
        """
        for step in steps:
            step["_composite_score"] = self.composite_score(step)
            step["_priority"] = self.map_priority(step["_composite_score"])
            step["_overdue"] = self.is_overdue(step)

        return sorted(
            steps,
            key=lambda s: (
                -s["_composite_score"],
                not s["_overdue"],
                (s.get("business_criticality", {}) or {}).get("criticality_tier", 3),
            ),
        )

    def critical_path(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Steps needing immediate action, overdue ones first.

        The prior implementation sorted ascending on the overdue flag,
        which put not-overdue items ahead of overdue ones inside the
        urgent bucket.
        """
        scored = self.score_steps(steps)
        urgent = [
            s for s in scored
            if s["_priority"] == "critical" or (s["_priority"] == "high" and s["_overdue"])
        ]
        remaining_high = [
            s for s in scored if s["_priority"] == "high" and s not in urgent
        ]
        urgent.sort(key=lambda s: (not s["_overdue"], -s["_composite_score"]))
        return urgent + remaining_high

    def rescore_with_new_evidence(
        self, steps: List[Dict[str, Any]], resolved: List[str]
    ) -> List[Dict[str, Any]]:
        """Re-prioritize after blind spots are closed.

        This is the seam Phase 03's re-orchestration loop plugs into: as
        an analyst answers questions, the plan reorders itself.
        """
        resolved_lower = {r.lower() for r in resolved}
        for step in steps:
            quality = step.get("evidence_quality")
            if not isinstance(quality, dict):
                continue
            before = list(quality.get("blind_spots", []) or [])
            quality["blind_spots"] = [
                spot for spot in before
                if not any(r in spot.lower() for r in resolved_lower)
            ]
            gaps = quality.get("evidence_gaps", {}) or {}
            quality["evidence_gaps"] = {
                k: v for k, v in gaps.items()
                if not any(r in k.lower() for r in resolved_lower)
            }
        return self.score_steps(steps)


def _clamp(value: float, lo: float = 0.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, value))
