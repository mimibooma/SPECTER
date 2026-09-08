"""
DFIR narrative and report generation.

The pipeline produces structured analysis: correlation output, an
investigation plan, enrichment. An analyst still has to turn that into a
written incident record for leadership, for a ticket, for a handoff. This
module does the deterministic assembly so the analyst edits rather than
starts from a blank page.

Two products:
  - A Markdown incident report: full record, evidence-cited, ready to edit.
  - An executive summary: five sentences a non-technical reader can act on.

Everything here is templating over facts the pipeline already established.
No model call, no invention. Where a fact is unknown it says so rather
than filling the gap.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

# ATT&CK tactic ordering, so a technique list reads as a kill chain rather
# than an arbitrary set.
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


class NarrativeGenerator:
    """Assembles incident reports from pipeline output."""

    def generate_report(self, result: Dict[str, Any]) -> str:
        pkg = result.get("evidence_package", {})
        plan = result.get("plan") or {}
        corr = pkg.get("correlation", {})
        intel = pkg.get("threat_intelligence", {})
        landscape = pkg.get("evidence_landscape", {})
        stats = pkg.get("collection_stats", {})

        persistence = result.get("persistence", {})
        playbook = result.get("containment_playbook", {})
        preserved = result.get("preserved")

        sections = [
            self._header(result, pkg, preserved),
            self._executive_summary(plan, corr, intel),
            self._what_we_know(corr, intel, persistence),
            self._attack_narrative(corr, plan),
            self._session_chains(corr),
            self._attack_patterns(corr),
            self._persistence(persistence),
            self._logging_gaps(corr),
            self._evidence_basis(landscape, stats),
            self._recommended_actions(plan),
            self._containment(playbook),
            self._appendix(intel, corr),
        ]
        return "\n\n".join(s for s in sections if s)

    def executive_brief(self, result: Dict[str, Any]) -> str:
        """Five sentences for someone who will never read the full report."""
        pkg = result.get("evidence_package", {})
        plan = result.get("plan") or {}
        corr = pkg.get("correlation", {}).get("summary", {})
        intel = pkg.get("threat_intelligence", {})

        actors = corr.get("distinct_actors", 0)
        gaps = corr.get("logging_gaps_detected", 0)
        chains = corr.get("escalation_chains", 0)
        groups = intel.get("attributed_groups", [])

        lines = []
        summary = plan.get("environment_summary")
        lines.append(summary if summary else
                     "An investigation was conducted across the in-scope AWS accounts.")

        if groups:
            lines.append(
                f"Activity was attributed with varying confidence to {_join(groups)}, "
                f"based on threat-intelligence matches against observed indicators."
            )

        if chains:
            lines.append(
                f"{chains} privilege-escalation sequence(s) were identified, where "
                f"account access was followed within minutes by permission changes."
            )

        if gaps:
            lines.append(
                f"Investigators identified {gaps} window(s) where security logging was "
                f"deliberately disabled, meaning some attacker activity was not recorded "
                f"and the picture is a floor, not a complete account."
            )

        crit = [s for s in plan.get("investigation_plan", [])
                if s.get("_priority") == "critical"]
        if crit:
            lines.append(
                f"{len(crit)} action(s) require immediate response; the highest priority "
                f"is: {crit[0].get('action', 'see full report')}."
            )
        else:
            lines.append("Recommended next actions are detailed in the full report.")

        return " ".join(lines)

    # ------------------------------------------------------------------

    def _header(self, result, pkg, preserved=None) -> str:
        generated = result.get("generated_at", _now())
        landscape = pkg.get("evidence_landscape", {})
        window = pkg.get("collection_window", {})
        custody = ""
        if preserved:
            custody = (f"**Evidence bundle:** `{preserved.get('path')}`  \n"
                       f"**Manifest SHA-256:** `{preserved.get('manifest_sha256')}`  \n")
        return (
            f"# Cloud Incident Investigation Report\n\n"
            f"**Generated:** {generated}  \n"
            f"**Tool:** SPECTER (Systematic Priority Engine for Cloud Threat "
            f"Evidence Reconstruction)  \n"
            f"**Accounts examined:** {landscape.get('accounts_examined', 'n/a')}  \n"
            f"**Collection window:** {window.get('start', 'n/a')} to "
            f"{window.get('end', 'n/a')}  \n"
            f"{custody}"
            f"**Classification:** _[set per your handling requirements]_\n\n"
            f"> This report was assembled automatically from correlated cloud "
            f"telemetry. Every claim traces to evidence cited in the Evidence "
            f"Basis section. Analyst review and validation is required before "
            f"any operational or legal use."
        )

    def _executive_summary(self, plan, corr, intel) -> str:
        summary = plan.get("environment_summary", "")
        confidence = plan.get("confidence_statement", "")
        body = summary or "_Pending analyst summary._"
        out = f"## Executive Summary\n\n{body}"
        if confidence:
            out += f"\n\n**Confidence:** {confidence}"
        hypotheses = plan.get("key_hypotheses", [])
        if hypotheses:
            out += "\n\n**Leading hypotheses:**\n"
            out += "\n".join(f"- {h}" for h in hypotheses)
        return out

    def _what_we_know(self, corr, intel, persistence=None) -> str:
        summary = corr.get("summary", {})
        persistence = persistence or {}
        rows = [
            ("Distinct actors observed", summary.get("distinct_actors", 0)),
            ("Actors crossing account boundaries", summary.get("cross_account_actors", 0)),
            ("Privilege-escalation sequences", summary.get("escalation_chains", 0)),
            ("Assumed-role session chains", summary.get("session_chains", 0)),
            ("Named attack patterns", summary.get("attack_patterns", 0)),
            ("Persistence findings (critical/high)", persistence.get("critical_or_high", 0)),
            ("Logging gaps detected", summary.get("logging_gaps_detected", 0)),
            ("  of which still open", summary.get("open_logging_gaps", 0)),
            ("Indicators extracted", intel.get("iocs_extracted", 0)),
            ("Indicators matched to threat intel", intel.get("iocs_enriched", 0)),
        ]
        table = "\n".join(f"| {label} | {value} |" for label, value in rows)
        out = (
            "## What We Know\n\n"
            "| Finding | Count |\n|---|---|\n" + table
        )
        groups = intel.get("attributed_groups", [])
        if groups:
            out += (
                f"\n\n**Threat attribution:** indicators matched infrastructure "
                f"associated with {_join(groups)}. Attribution from indicator "
                f"matches is suggestive, not conclusive; treat as a lead."
            )
        if intel.get("enrichment_degraded"):
            out += (
                "\n\n> **Note:** threat-intelligence feeds were unavailable for this "
                "run. Indicators were extracted but not enriched, so no attribution "
                "or reputation data is reflected above."
            )
        return out

    def _attack_narrative(self, corr, plan) -> str:
        """Reconstruct the sequence as prose, ordered by kill-chain phase."""
        pivots = corr.get("cross_account_pivots", [])
        chains = corr.get("escalation_chains", [])
        sequences = corr.get("guardduty_attack_sequences", [])

        parts = ["## Reconstructed Activity"]

        if sequences:
            parts.append(
                "**GuardDuty attack sequences.** Amazon GuardDuty's own multi-stage "
                "correlation flagged the following, which anchor this reconstruction:"
            )
            for seq in sequences:
                parts.append(
                    f"- **{seq.get('title', 'Attack sequence')}** "
                    f"(severity {seq.get('severity', '?')}, "
                    f"{seq.get('signal_count', 0)} correlated signals) in account "
                    f"{seq.get('account', '?')}/{seq.get('region', '?')}"
                )

        if chains:
            parts.append("\n**Privilege-escalation sequences.** In each case, account "
                         "access was followed within the correlation window by permission "
                         "changes, the signature pattern of credential misuse:")
            for c in chains:
                escalations = ", ".join(e["event"] for e in c.get("escalation_events", []))
                mfa = c.get("mfa")
                mfa_note = " (no MFA on the access event)" if mfa in ("false", False) else ""
                actor = _short_actor(c.get("actor", "unknown"))
                parts.append(
                    f"- `{actor}` performed **{c.get('access_event')}** from "
                    f"`{c.get('source_ip', 'unknown IP')}`{mfa_note}, then within "
                    f"{int(c.get('window_minutes', 15))} minutes: **{escalations}**"
                )

        if pivots:
            parts.append("\n**Cross-account movement.** Role assumptions crossed account "
                         "boundaries, indicating movement through the environment:")
            for p in pivots:
                parts.append(
                    f"- `{_short_actor(p.get('actor', '?'))}` assumed a role from account "
                    f"{p.get('source_account')} into {p.get('target_account')} "
                    f"(`{p.get('target_role', '')}`)"
                )

        if len(parts) == 1:
            parts.append("_No multi-stage sequences were correlated from the available "
                         "evidence. This may mean the activity was isolated or, where "
                         "logging gaps exist, an incomplete record._")
        return "\n".join(parts)

    def _session_chains(self, corr) -> str:
        chains = corr.get("session_chains", [])
        if not chains:
            return ""
        parts = ["## Assumed-Role Sessions",
                 "Each AssumeRole mints a temp key; every later action under that key "
                 "is attributable to whoever assumed the role. This is how activity "
                 "gets traced back through pivots."]
        for c in chains[:8]:
            who = _short_actor(c.get("assumed_by", "?"))
            role = (c.get("role") or "?").split("/")[-1]
            notable = ", ".join(c.get("notable", [])) or "none flagged"
            parts.append(f"- `{who}` assumed **{role}** at {c.get('assumed_at')} from "
                         f"`{c.get('source_ip', '?')}`; {c.get('action_count', 0)} action(s). "
                         f"Notable: {notable}")
        return "\n".join(parts)

    def _attack_patterns(self, corr) -> str:
        pats = corr.get("attack_patterns", [])
        if not pats:
            return ""
        parts = ["## Recognized Attack Patterns",
                 "Event clusters matching patterns from the AWS Threat Technique "
                 "Catalog. Heuristic, not proof; each names what to go verify."]
        for p in pats:
            parts.append(f"- **{p.get('pattern', '').replace('_', ' ').title()}** "
                         f"({p.get('severity', '?')}) by `{_short_actor(p.get('actor', '?'))}`: "
                         f"{p.get('detail')}. [{p.get('technique')}]({p.get('ttc_url', '')}) "
                         f"{p.get('technique_name', '')}")
        return "\n".join(parts)

    def _persistence(self, persistence) -> str:
        findings = (persistence or {}).get("findings", [])
        if not findings:
            return ""
        parts = ["## Persistence Findings",
                 f"{len(findings)} finding(s), {persistence.get('critical_or_high', 0)} "
                 f"critical or high. Items marked likely automation come from principals "
                 f"that look like deploy pipelines; lower confidence."]
        for f in findings[:12]:
            auto = " _(likely automation)_" if f.get("likely_automation") else ""
            src = " _(live state)_" if f.get("source") == "live_state" else ""
            parts.append(f"- **{f.get('severity', '?').upper()}** {f.get('detail')}{auto}{src}  \n"
                         f"  Actor: `{_short_actor(f.get('actor', '?'))}` · "
                         f"{f.get('account')}/{f.get('region')} · "
                         f"[{f.get('technique')}]({f.get('ttc_url', '')})")
        if len(findings) > 12:
            parts.append(f"- _{len(findings) - 12} more in JSON output_")
        return "\n".join(parts)

    def _containment(self, playbook) -> str:
        if not playbook or not (playbook.get("immediate") or playbook.get("short_term")):
            return ""
        parts = ["## Containment Playbook (Recommended, Not Executed)",
                 f"_{playbook.get('disclaimer', '')}_"]
        if playbook.get("compromised_principals"):
            parts.append("\n**Principals to contain:** " +
                         ", ".join(f"`{_short_actor(a)}`" for a in playbook["compromised_principals"]))
        for label, key in (("Immediate", "immediate"), ("Short-term", "short_term"),
                           ("Verify", "verify")):
            steps = playbook.get(key, [])
            if not steps:
                continue
            parts.append(f"\n### {label}")
            for s in steps:
                parts.append(f"**{s.get('action')}**  \n_{s.get('why', '')}_")
                parts.append("```bash\n" + "\n".join(s.get("commands", [])) + "\n```")
        return "\n".join(parts)

    def _logging_gaps(self, corr) -> str:
        gaps = corr.get("logging_gaps", [])
        if not gaps:
            return ""
        parts = ["## Logging Gaps (Evidence Suppression)"]
        parts.append(
            "The following windows show security logging being deliberately disabled. "
            "Absence of evidence during these windows is **not** evidence of absence; "
            "any activity here went unrecorded and the reconstruction understates it."
        )
        for g in gaps:
            if g.get("still_open"):
                parts.append(
                    f"- **OPEN GAP** on `{g.get('resource')}` in "
                    f"{g.get('account')}/{g.get('region')}: "
                    f"`{g.get('disable_event')}` by `{_short_actor(g.get('disabled_by', '?'))}` "
                    f"at {g.get('start')}, never re-enabled in the collection window."
                )
            else:
                during = g.get("events_during_gap", 0)
                during_note = (
                    f" **{during} event(s) occurred during this gap.**" if during else ""
                )
                parts.append(
                    f"- {g.get('duration_minutes')}-minute gap on `{g.get('resource')}` "
                    f"in {g.get('account')}/{g.get('region')}: "
                    f"`{g.get('disable_event')}` -> re-enabled, by "
                    f"`{_short_actor(g.get('disabled_by', '?'))}`.{during_note}"
                )
        return "\n".join(parts)

    def _evidence_basis(self, landscape, stats) -> str:
        parts = ["## Evidence Basis"]
        parts.append(
            f"Collection examined {landscape.get('account_regions_examined', 0)} "
            f"account/region pairs, of which {landscape.get('account_regions_reachable', 0)} "
            f"were reachable. Mean forensic readiness across reachable environments was "
            f"**{landscape.get('mean_readiness_score', 0)}/100**."
        )
        parts.append(
            f"\nOf {stats.get('raw_events', 0):,} raw events, "
            f"{stats.get('selected', 0):,} were selected for analysis after filtering "
            f"and deduplication (a {stats.get('reduction_ratio', 0) * 100:.1f}% reduction). "
            f"Selection prioritizes security-relevant, high-signal events; the full raw "
            f"set is preserved at source for audit."
        )

        blind = landscape.get("regions_without_active_cloudtrail", [])
        if blind:
            parts.append(
                f"\n**Coverage gaps.** {len(blind)} account/region(s) had no active "
                f"CloudTrail during the window: {_join(blind[:8])}"
                + (f", and {len(blind) - 8} more" if len(blind) > 8 else "")
                + ". Activity in these is not represented in this report."
            )
        gap_freq = landscape.get("gap_frequency", {})
        if gap_freq:
            parts.append("\n**Most common readiness gaps across the estate:**")
            for gap, count in list(gap_freq.items())[:5]:
                parts.append(f"- {gap} ({count} account/regions)")
        return "\n".join(parts)

    def _recommended_actions(self, plan) -> str:
        steps = plan.get("investigation_plan", [])
        if not steps:
            return ""
        parts = ["## Recommended Actions (Prioritized)"]
        parts.append(
            "Ordered by composite priority: business impact, threat confidence, "
            "response effort, and evidence quality. Priority and score are shown "
            "for each."
        )
        for step in steps:
            pri = step.get("_priority", "medium").upper()
            score = step.get("_composite_score", "")
            overdue = " **[OVERDUE]**" if step.get("_overdue") else ""
            parts.append(f"\n### {pri} ({score}/10){overdue} — {step.get('action', '')}")
            if step.get("attack_technique_id"):
                parts.append(
                    f"- **ATT&CK:** {step['attack_technique_id']} "
                    f"{step.get('attack_technique_name', '')} "
                    f"({step.get('mitre_tactic', 'n/a')})"
                )
            if step.get("rationale"):
                parts.append(f"- **Rationale:** {step['rationale']}")
            if step.get("evidence_sources"):
                parts.append(f"- **Evidence:** {', '.join(step['evidence_sources'])}")
            if step.get("affected_accounts"):
                parts.append(f"- **Accounts:** {', '.join(step['affected_accounts'])}")
        return "\n".join(parts)

    def _appendix(self, intel, corr) -> str:
        malicious = intel.get("malicious_iocs", [])
        if not malicious:
            return ""
        parts = ["## Appendix: Indicators of Compromise"]
        parts.append("| Indicator | Type | Confidence | Attribution | Context |")
        parts.append("|---|---|---|---|---|")
        for ioc in malicious:
            groups = ", ".join(ioc.get("threat_groups", [])) or "-"
            parts.append(
                f"| `{ioc.get('value')}` | {ioc.get('type')} | "
                f"{ioc.get('confidence')}% | {groups} | "
                f"{ioc.get('context', '')[:50]} |"
            )
        return "\n".join(parts)


# ----------------------------------------------------------------------


def _join(items: List[str]) -> str:
    items = [str(i) for i in items]
    if not items:
        return "none"
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def _short_actor(arn: str) -> str:
    """Trim an ARN to its final component for readability."""
    if not arn or arn == "unknown":
        return "unknown principal"
    return arn.split("/")[-1] if "/" in arn else arn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
