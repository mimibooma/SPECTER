"""
Regression tests for SPECTER Phase 02.

Each test in TestRegressionFixes maps to a specific defect found in the
prior draft. They exist so the same bugs cannot return silently.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.scoring_engine import (  # noqa: E402
    ScoringEngine, resolve_threat_group, THREAT_GROUPS,
)
from services.correlation_engine import CorrelationEngine  # noqa: E402
from services.evidence_collector import EvidenceCollector, EVENT_GROUPS  # noqa: E402
from services.threat_intel import IOCExtractor, ThreatIntelService  # noqa: E402
from services.account_broker import AccountTarget  # noqa: E402


class TestRegressionFixes(unittest.TestCase):
    """One test per defect identified in the prior implementation."""

    def setUp(self):
        self.engine = ScoringEngine()

    def test_composite_score_reaches_critical_band(self):
        """BUG 1: dividing by 10 after weighting made 'critical' unreachable.

        A maximally severe step must land in the critical band. Under the
        old formula the highest achievable score was ~1.0 against a 7.5
        threshold, so nothing was ever critical.
        """
        step = {
            "business_criticality": {
                "criticality_tier": 1,
                "impact_if_compromised": "severe",
                "data_sensitivity": "pci",
                "sla_breach_risk": True,
            },
            "threat_intel_enrichment": {
                "confidence": 95,
                "associated_threat_groups": ["APT29"],
                "linked_iocs": ["1.2.3.4", "evil.com", "bad.net"],
                "data_sources": ["feed_a", "feed_b"],
            },
            "evidence_quality": {
                "completeness": 95, "reliability": 95,
                "confidence": 95, "blind_spots": [],
            },
            "response_effort": 1,
        }
        score = self.engine.composite_score(step)
        self.assertGreaterEqual(score, 7.5, f"expected critical band, got {score}")
        self.assertEqual(self.engine.map_priority(score), "critical")

    def test_low_severity_stays_low(self):
        """Scoring must still discriminate: a trivial step must not be critical."""
        step = {
            "business_criticality": {
                "criticality_tier": 4,
                "impact_if_compromised": "low",
                "data_sensitivity": "public",
                "sla_breach_risk": False,
            },
            "threat_intel_enrichment": {"confidence": 10},
            "evidence_quality": {
                "completeness": 20, "reliability": 20, "confidence": 20,
                "blind_spots": ["no logs", "no flow logs"],
            },
            "response_effort": 5,
        }
        score = self.engine.composite_score(step)
        self.assertLess(score, 5.0, f"expected low/medium, got {score}")

    def test_evidence_quality_not_saturated(self):
        """BUG 2: summing three 0-10 values then clamping pinned everything at 10."""
        mediocre = self.engine.evidence_quality(
            {"completeness": 40, "reliability": 40, "confidence": 40}
        )
        excellent = self.engine.evidence_quality(
            {"completeness": 100, "reliability": 100, "confidence": 100}
        )
        self.assertLess(mediocre, 5.0, f"mediocre evidence scored {mediocre}")
        self.assertAlmostEqual(excellent, 10.0, places=1)
        self.assertGreater(excellent - mediocre, 4.0,
                           "scoring must discriminate evidence quality")

    def test_evidence_quality_penalizes_blind_spots(self):
        base = {"completeness": 90, "reliability": 90, "confidence": 90}
        clean = self.engine.evidence_quality(dict(base, blind_spots=[]))
        blind = self.engine.evidence_quality(
            dict(base, blind_spots=["CloudTrail gap", "No flow logs"])
        )
        self.assertLess(blind, clean)

    def test_more_analysts_reduces_effort(self):
        """BUG 3: adding analysts previously increased the effort score."""
        solo = self.engine.response_effort(4, analysts=1)
        team = self.engine.response_effort(4, analysts=3)
        self.assertLess(team, solo,
                        f"3 analysts ({team}) should beat 1 ({solo})")

    def test_critical_path_puts_overdue_first(self):
        """BUG 4: ascending sort on the overdue flag buried overdue items."""
        steps = [
            {
                "step": 1,
                "business_criticality": {"criticality_tier": 1,
                                         "impact_if_compromised": "severe",
                                         "data_sensitivity": "pci",
                                         "sla_breach_risk": True},
                "threat_intel_enrichment": {"confidence": 90},
                "evidence_quality": {"completeness": 90, "reliability": 90,
                                     "confidence": 90},
                "response_effort": 1,
                "time_sensitivity": {"incident_age_hours": 1,
                                     "optimal_response_window_hours": 4},
            },
            {
                "step": 2,
                "business_criticality": {"criticality_tier": 1,
                                         "impact_if_compromised": "severe",
                                         "data_sensitivity": "pci",
                                         "sla_breach_risk": True},
                "threat_intel_enrichment": {"confidence": 90},
                "evidence_quality": {"completeness": 90, "reliability": 90,
                                     "confidence": 90},
                "response_effort": 1,
                "time_sensitivity": {"incident_age_hours": 20,
                                     "optimal_response_window_hours": 4},
            },
        ]
        path = self.engine.critical_path(steps)
        self.assertTrue(path[0]["_overdue"],
                        "overdue step must surface first on the critical path")
        self.assertEqual(path[0]["step"], 2)

    def test_threat_group_aliases_resolve(self):
        """BUG 5: hardcoded name list missed aliases for the same group."""
        self.assertEqual(resolve_threat_group("APT29"), "G0016")
        self.assertEqual(resolve_threat_group("Cozy Bear"), "G0016")
        self.assertEqual(resolve_threat_group("Midnight Blizzard"), "G0016")
        self.assertEqual(
            resolve_threat_group("APT29"), resolve_threat_group("cozy bear"),
            "aliases for one group must resolve identically",
        )
        self.assertIsNone(resolve_threat_group("Not A Real Group"))

    def test_group_ids_use_g_prefix(self):
        """BUG 6: threat actors were tagged with T-prefixed technique IDs."""
        for gid in THREAT_GROUPS:
            self.assertTrue(gid.startswith("G"),
                            f"{gid} must be an ATT&CK group ID, not a technique ID")

    def test_alias_resolution_feeds_confidence(self):
        """An aliased state actor must raise confidence like its canonical name."""
        canonical = self.engine.threat_confidence(
            {"confidence": 70, "associated_threat_groups": ["APT29"]}
        )
        aliased = self.engine.threat_confidence(
            {"confidence": 70, "associated_threat_groups": ["Midnight Blizzard"]}
        )
        self.assertEqual(canonical, aliased)
        unknown = self.engine.threat_confidence({"confidence": 70})
        self.assertGreater(canonical, unknown)


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.engine = CorrelationEngine(time_window_minutes=15)

    def test_detects_closed_logging_gap(self):
        events = [
            {"eventTime": "2026-09-01T03:26:58Z", "eventName": "StopLogging",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "awsRegion": "us-east-1",
             "requestParameters": {"name": "org-trail"}},
            {"eventTime": "2026-09-01T03:31:00Z", "eventName": "GetObject",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "awsRegion": "us-east-1"},
            {"eventTime": "2026-09-01T03:40:02Z", "eventName": "StartLogging",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "awsRegion": "us-east-1",
             "requestParameters": {"name": "org-trail"}},
        ]
        result = self.engine.correlate(events, [])
        gaps = result["logging_gaps"]
        self.assertEqual(len(gaps), 1)
        self.assertAlmostEqual(gaps[0]["duration_minutes"], 13.1, places=0)
        self.assertFalse(gaps[0]["still_open"])
        self.assertEqual(gaps[0]["events_during_gap"], 1,
                         "activity inside the gap must be counted")

    def test_detects_open_logging_gap(self):
        events = [
            {"eventTime": "2026-09-01T03:26:58Z", "eventName": "StopLogging",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "awsRegion": "us-east-1",
             "requestParameters": {"name": "org-trail"}},
        ]
        result = self.engine.correlate(events, [])
        self.assertTrue(result["logging_gaps"][0]["still_open"])
        self.assertEqual(result["summary"]["open_logging_gaps"], 1)

    def test_detects_escalation_chain(self):
        events = [
            {"eventTime": "2026-09-01T03:14:22Z", "eventName": "ConsoleLogin",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "sourceIPAddress": "185.220.101.47",
             "mfaAuthenticated": "false"},
            {"eventTime": "2026-09-01T03:19:03Z", "eventName": "CreateAccessKey",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "sourceIPAddress": "185.220.101.47"},
        ]
        result = self.engine.correlate(events, [])
        chains = result["escalation_chains"]
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["access_event"], "ConsoleLogin")
        self.assertEqual(chains[0]["escalation_events"][0]["event"], "CreateAccessKey")

    def test_ignores_escalation_outside_window(self):
        events = [
            {"eventTime": "2026-09-01T03:00:00Z", "eventName": "ConsoleLogin",
             "actor": {"arn": "arn:aws:iam::1:user/svc"}, "account": "1"},
            {"eventTime": "2026-09-01T09:00:00Z", "eventName": "CreateAccessKey",
             "actor": {"arn": "arn:aws:iam::1:user/svc"}, "account": "1"},
        ]
        result = self.engine.correlate(events, [])
        self.assertEqual(len(result["escalation_chains"]), 0)

    def test_detects_cross_account_pivot(self):
        events = [
            {"eventTime": "2026-09-01T03:29:15Z", "eventName": "AssumeRole",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333", "sourceIPAddress": "185.220.101.47",
             "requestParameters": {
                 "roleArn": "arn:aws:iam::998877665544:role/OrgFinanceAdminRole"}},
        ]
        result = self.engine.correlate(events, [])
        pivots = result["cross_account_pivots"]
        self.assertEqual(len(pivots), 1)
        self.assertEqual(pivots[0]["target_account"], "998877665544")

    def test_actor_timeline_flags_cross_account(self):
        events = [
            {"eventTime": "2026-09-01T03:00:00Z", "eventName": "ConsoleLogin",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "111122223333"},
            {"eventTime": "2026-09-01T03:05:00Z", "eventName": "GetObject",
             "actor": {"arn": "arn:aws:iam::111122223333:user/svc"},
             "account": "998877665544"},
        ]
        result = self.engine.correlate(events, [])
        tl = result["actor_timelines"][0]
        self.assertTrue(tl["cross_account"])
        self.assertEqual(len(tl["accounts_touched"]), 2)


class TestEvidenceReduction(unittest.TestCase):
    def setUp(self):
        self.collector = EvidenceCollector(broker=None)

    def test_allowlist_covers_key_techniques(self):
        allowed = self.collector.allowed_events
        for critical in ("StopLogging", "CreateAccessKey", "AttachUserPolicy",
                         "ConsoleLogin", "AssumeRole", "GetObject"):
            self.assertIn(critical, allowed)

    def test_deduplication_collapses_runs(self):
        events = [
            {"eventName": "ListBuckets", "actor": {"arn": "a"},
             "sourceIPAddress": "1.1.1.1", "eventTime": f"2026-09-01T03:{i:02d}:00Z"}
            for i in range(30)
        ]
        deduped, clusters = self.collector._deduplicate(events)
        self.assertEqual(len(deduped), 2, "a run of identical calls keeps only endpoints")
        self.assertEqual(clusters, 1)
        self.assertEqual(deduped[0]["_specter_repeat_count"], 30,
                         "collapsed volume must remain visible")

    def test_dedup_preserves_small_groups(self):
        events = [
            {"eventName": "ConsoleLogin", "actor": {"arn": "a"},
             "sourceIPAddress": "1.1.1.1", "eventTime": "2026-09-01T03:00:00Z"},
            {"eventName": "ConsoleLogin", "actor": {"arn": "a"},
             "sourceIPAddress": "1.1.1.1", "eventTime": "2026-09-01T03:01:00Z"},
        ]
        deduped, _ = self.collector._deduplicate(events)
        self.assertEqual(len(deduped), 2)

    def test_budget_prioritizes_critical_events(self):
        events = [
            {"eventName": "ListBuckets", "eventTime": f"2026-09-01T01:{i:02d}:00Z",
             "userIdentity": {"arn": f"arn:aws:iam::1:user/u{i}"},
             "sourceIPAddress": "10.0.0.1"}
            for i in range(50)
        ] + [
            {"eventName": "StopLogging", "eventTime": "2026-09-01T02:00:00Z",
             "userIdentity": {"arn": "arn:aws:iam::1:user/attacker"},
             "sourceIPAddress": "185.220.101.47"},
        ]
        selected = self.collector._apply_budget(events, token_budget=300)
        names = [e["eventName"] for e in selected]
        self.assertIn("StopLogging", names,
                      "critical events must survive a tight budget")

    def test_budget_output_is_chronological(self):
        events = [
            {"eventName": "StopLogging", "eventTime": "2026-09-01T05:00:00Z",
             "userIdentity": {"arn": "a"}},
            {"eventName": "ConsoleLogin", "eventTime": "2026-09-01T01:00:00Z",
             "userIdentity": {"arn": "a"}},
        ]
        selected = self.collector._apply_budget(events, token_budget=10_000)
        times = [e["eventTime"] for e in selected]
        self.assertEqual(times, sorted(times),
                         "model must receive a chronological timeline")

    def test_slim_reduces_payload_size(self):
        fat = {
            "eventTime": "2026-09-01T03:00:00Z", "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com", "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4", "userAgent": "x" * 400,
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/u",
                             "accessKeyId": "AKIA...", "principalId": "P" * 100},
            "responseElements": {"junk": "y" * 3000},
            "additionalEventData": {"more": "z" * 2000},
        }
        import json
        slim = self.collector._slim(fat)
        self.assertLess(len(json.dumps(slim)), len(json.dumps(fat)) / 3)
        self.assertEqual(slim["eventName"], "GetObject")
        self.assertNotIn("responseElements", slim)


class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        self.extractor = IOCExtractor()

    def test_extracts_public_ip(self):
        events = [{"sourceIPAddress": "185.220.101.47", "eventName": "ConsoleLogin",
                   "actor": {"arn": "a"}}]
        iocs = self.extractor.extract_from_events(events)
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0].value, "185.220.101.47")

    def test_skips_private_ips(self):
        """RFC1918 addresses are not indicators and must not be enriched."""
        for private in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"):
            events = [{"sourceIPAddress": private, "eventName": "X",
                       "actor": {"arn": "a"}}]
            self.assertEqual(len(self.extractor.extract_from_events(events)), 0,
                             f"{private} must not be treated as an IOC")

    def test_extracts_ip_from_guardduty_text(self):
        findings = [{
            "Type": "UnauthorizedAccess:IAMUser/TorIPCaller",
            "Description": "API calls from Tor exit node 185.220.101.47 observed",
            "Id": "f1",
        }]
        iocs = self.extractor.extract_from_findings(findings)
        self.assertTrue(any(i.value == "185.220.101.47" for i in iocs))

    def test_denylists_aws_domains(self):
        findings = [{"Description": "call to s3.amazonaws.com and evil-c2.top",
                     "Type": "T", "Id": "f"}]
        domains = {i.value for i in self.extractor.extract_from_findings(findings)
                   if i.ioc_type == "domain"}
        self.assertIn("evil-c2.top", domains)
        self.assertNotIn("s3.amazonaws.com", domains)

    def test_degrades_without_feeds(self):
        svc = ThreatIntelService(feed_dir="/nonexistent/path")
        self.assertTrue(svc.degraded)
        result = svc.analyze(
            [{"sourceIPAddress": "185.220.101.47", "eventName": "X",
              "actor": {"arn": "a"}}], []
        )
        self.assertTrue(result["enrichment_degraded"])
        self.assertEqual(result["iocs_enriched"], 0)
        self.assertGreater(result["iocs_extracted"], 0,
                           "extraction must still work without feeds")


class TestAccountBroker(unittest.TestCase):
    def test_role_arn_construction(self):
        t = AccountTarget(account_id="111122223333", role_name="IRRole")
        self.assertEqual(t.role_arn, "arn:aws:iam::111122223333:role/IRRole")

    def test_govcloud_partition_arn(self):
        t = AccountTarget(account_id="111122223333", role_name="IRRole")
        self.assertEqual(t.gov_role_arn(),
                         "arn:aws-us-gov:iam::111122223333:role/IRRole")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestNarrative(unittest.TestCase):
    """Narrative generation from pipeline output."""

    def setUp(self):
        from services.narrative_generator import NarrativeGenerator
        self.gen = NarrativeGenerator()
        self.result = {
            "generated_at": "2026-09-03T12:00:00Z",
            "evidence_package": {
                "evidence_landscape": {
                    "accounts_examined": 3,
                    "account_regions_examined": 6,
                    "account_regions_reachable": 5,
                    "mean_readiness_score": 62.0,
                    "regions_without_active_cloudtrail": ["999/us-west-2"],
                    "gap_frequency": {"No VPC flow logs": 3},
                },
                "collection_stats": {
                    "raw_events": 50000, "selected": 180, "reduction_ratio": 0.9964,
                },
                "collection_window": {"start": "2026-09-01T00:00:00Z",
                                      "end": "2026-09-03T00:00:00Z"},
                "correlation": {
                    "summary": {"distinct_actors": 2, "cross_account_actors": 1,
                                "escalation_chains": 1, "logging_gaps_detected": 1,
                                "open_logging_gaps": 0},
                    "logging_gaps": [{
                        "duration_minutes": 13.1, "resource": "org-trail",
                        "account": "111", "region": "us-east-1",
                        "disable_event": "StopLogging",
                        "disabled_by": "arn:aws:iam::111:user/svc",
                        "still_open": False, "events_during_gap": 3,
                    }],
                    "escalation_chains": [{
                        "actor": "arn:aws:iam::111:user/svc",
                        "access_event": "ConsoleLogin", "source_ip": "185.220.101.47",
                        "mfa": "false", "window_minutes": 15,
                        "escalation_events": [{"event": "CreateAccessKey"}],
                    }],
                    "cross_account_pivots": [{
                        "actor": "arn:aws:iam::111:user/svc",
                        "source_account": "111", "target_account": "222",
                        "target_role": "arn:aws:iam::222:role/Admin",
                    }],
                    "guardduty_attack_sequences": [],
                },
                "threat_intelligence": {
                    "iocs_extracted": 4, "iocs_enriched": 2,
                    "attributed_groups": ["APT28"], "enrichment_degraded": False,
                    "malicious_iocs": [{
                        "value": "104.244.76.100", "type": "ip", "confidence": 95,
                        "threat_groups": ["G0007"], "context": "AssumeRole",
                    }],
                },
            },
            "plan": {
                "environment_summary": "Credential compromise with cross-account movement.",
                "confidence_statement": "High confidence on the escalation chain.",
                "key_hypotheses": ["Stolen keys used from a Tor exit node."],
                "investigation_plan": [{
                    "step": 1, "action": "Revoke compromised keys",
                    "attack_technique_id": "T1078.004",
                    "attack_technique_name": "Cloud Accounts",
                    "mitre_tactic": "Persistence",
                    "_priority": "critical", "_composite_score": 9.5, "_overdue": True,
                    "rationale": "Active credential in use.",
                    "evidence_sources": ["CloudTrail", "GuardDuty"],
                }],
            },
        }

    def test_report_contains_all_sections(self):
        report = self.gen.generate_report(self.result)
        for heading in ["# Cloud Incident Investigation Report", "## Executive Summary",
                        "## What We Know", "## Reconstructed Activity",
                        "## Logging Gaps", "## Evidence Basis",
                        "## Recommended Actions", "## Appendix"]:
            self.assertIn(heading, report, f"missing section: {heading}")

    def test_report_cites_escalation_and_gap(self):
        report = self.gen.generate_report(self.result)
        self.assertIn("ConsoleLogin", report)
        self.assertIn("CreateAccessKey", report)
        self.assertIn("13.1-minute gap", report)
        self.assertIn("no MFA", report)

    def test_report_flags_events_during_gap(self):
        report = self.gen.generate_report(self.result)
        self.assertIn("3 event(s) occurred during this gap", report)

    def test_executive_brief_is_concise(self):
        brief = self.gen.executive_brief(self.result)
        self.assertIn("APT28", brief)
        self.assertLessEqual(len(brief.split(". ")), 6,
                             "executive brief should stay near five sentences")

    def test_degraded_enrichment_noted(self):
        self.result["evidence_package"]["threat_intelligence"]["enrichment_degraded"] = True
        report = self.gen.generate_report(self.result)
        self.assertIn("feeds were unavailable", report)


class TestAthenaQuery(unittest.TestCase):
    """Athena query construction (no live AWS)."""

    def _config(self, source="cloudtrail"):
        from services.athena_collector import AthenaConfig
        return AthenaConfig(database="sec", table="cloudtrail_logs",
                            output_location="s3://results/", source_type=source)

    def test_cloudtrail_query_has_partition_pruning(self):
        from services.athena_collector import AthenaCollector
        from datetime import datetime, timezone
        c = AthenaCollector(session=None, config=self._config())
        sql = c._build_query(
            ["111", "222"], ["us-east-1"],
            datetime(2026, 9, 1, tzinfo=timezone.utc),
            datetime(2026, 9, 3, tzinfo=timezone.utc),
            {"StopLogging", "CreateAccessKey"}, None, 20000,
        )
        self.assertIn("BETWEEN '20260901' AND '20260903'", sql)
        self.assertIn("eventname IN", sql)
        self.assertIn("'111', '222'", sql)
        self.assertIn("LIMIT 20000", sql)

    def test_security_lake_uses_ocsf_columns(self):
        from services.athena_collector import AthenaCollector
        from datetime import datetime, timezone
        c = AthenaCollector(session=None, config=self._config("security_lake"))
        sql = c._build_query(
            ["111"], [],
            datetime(2026, 9, 1, tzinfo=timezone.utc),
            datetime(2026, 9, 3, tzinfo=timezone.utc),
            {"StopLogging"}, None, 5000,
        )
        self.assertIn("api.operation", sql)
        self.assertIn("cloud.account.uid", sql)
        self.assertIn("eventday BETWEEN", sql)

    def test_actor_predicate_added_when_scoped(self):
        from services.athena_collector import AthenaCollector
        from datetime import datetime, timezone
        c = AthenaCollector(session=None, config=self._config())
        sql = c._build_query(
            ["111"], [], datetime(2026, 9, 1, tzinfo=timezone.utc),
            datetime(2026, 9, 3, tzinfo=timezone.utc),
            {"StopLogging"}, {"attacker-role"}, 5000,
        )
        self.assertIn("LIKE '%attacker-role%'", sql)

    def test_sql_escaping(self):
        from services.athena_collector import _escape
        self.assertEqual(_escape("o'brien"), "o''brien")


class TestPersistenceHunter(unittest.TestCase):
    def setUp(self):
        from services.persistence_hunter import PersistenceHunter
        self.h = PersistenceHunter(broker=None)

    def test_flags_backdoor_user_creation(self):
        events = [{"eventName": "CreateUser", "eventTime": "2026-09-01T03:00:00Z",
                   "actor": {"arn": "arn:aws:iam::1:user/attacker"},
                   "account": "1", "awsRegion": "us-east-1",
                   "requestParameters": {"userName": "backdoor-svc"}}]
        f = self.h.hunt_events(events)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].mechanism, "iam_backdoor")
        self.assertEqual(f[0].resource, "backdoor-svc")
        self.assertEqual(f[0].technique, "T1136.003")

    def test_trust_policy_change_is_critical(self):
        events = [{"eventName": "UpdateAssumeRolePolicy", "eventTime": "2026-09-01T03:00:00Z",
                   "actor": {"arn": "arn:aws:iam::1:user/x"}, "account": "1",
                   "awsRegion": "us-east-1", "requestParameters": {"roleName": "Admin"}}]
        self.assertEqual(self.h.hunt_events(events)[0].severity, "critical")

    def test_automation_downgraded(self):
        events = [{"eventName": "CreateFunction", "eventTime": "2026-09-01T03:00:00Z",
                   "actor": {"arn": "arn:aws:iam::1:role/github-actions-deploy"},
                   "account": "1", "awsRegion": "us-east-1",
                   "requestParameters": {"functionName": "api"}}]
        f = self.h.hunt_events(events)
        self.assertTrue(f[0].likely_automation)
        self.assertEqual(f[0].severity, "low")

    def test_suspicious_actor_not_downgraded(self):
        events = [{"eventName": "CreateFunction", "eventTime": "2026-09-01T03:00:00Z",
                   "actor": {"arn": "arn:aws:iam::1:role/github-actions-deploy"},
                   "account": "1", "awsRegion": "us-east-1",
                   "requestParameters": {"functionName": "api"}}]
        f = self.h.hunt_events(events, suspicious_actors={"arn:aws:iam::1:role/github-actions-deploy"})
        self.assertEqual(f[0].severity, "high")

    def test_ttc_url_populated(self):
        events = [{"eventName": "DeactivateMFADevice", "eventTime": "2026-09-01T03:00:00Z",
                   "actor": {"arn": "a"}, "account": "1", "awsRegion": "us-east-1"}]
        f = self.h.hunt_events(events)
        self.assertIn("threat-technique-catalog-for-aws", f[0].ttc_url)
        self.assertIn("T1556.006", f[0].ttc_url)

    def test_external_trust_detection(self):
        from services.persistence_hunter import _external_principals
        trust = {"Statement": [{"Effect": "Allow",
                                "Principal": {"AWS": ["arn:aws:iam::999:root", "arn:aws:iam::111:root"]}}]}
        self.assertEqual(_external_principals(trust, "111"), {"arn:aws:iam::999:root"})
        self.assertIn("*", _external_principals({"Statement": [{"Effect": "Allow", "Principal": "*"}]}, "111"))


class TestSessionChains(unittest.TestCase):
    def test_links_assumerole_to_actions(self):
        from services.correlation_engine import CorrelationEngine
        events = [
            {"eventTime": "2026-09-01T03:00:00Z", "eventName": "AssumeRole",
             "actor": {"arn": "arn:aws:iam::1:user/svc"}, "account": "1", "sourceIPAddress": "1.2.3.4",
             "requestParameters": {"roleArn": "arn:aws:iam::2:role/Admin"},
             "responseElements": {"credentials": {"accessKeyId": "ASIATEMP123"}}},
            {"eventTime": "2026-09-01T03:05:00Z", "eventName": "CreateAccessKey",
             "actor": {"arn": "arn:aws:sts::2:assumed-role/Admin/svc"}, "accessKeyId": "ASIATEMP123", "account": "2"},
            {"eventTime": "2026-09-01T03:06:00Z", "eventName": "StopLogging",
             "actor": {"arn": "arn:aws:sts::2:assumed-role/Admin/svc"}, "accessKeyId": "ASIATEMP123", "account": "2"},
        ]
        chains = CorrelationEngine().correlate(events, [])["session_chains"]
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["assumed_by"], "arn:aws:iam::1:user/svc")
        self.assertEqual(chains[0]["action_count"], 2)
        self.assertIn("StopLogging", chains[0]["notable"])

    def test_no_chains_without_minted_keys(self):
        from services.correlation_engine import CorrelationEngine
        events = [{"eventTime": "2026-09-01T03:00:00Z", "eventName": "ListBuckets", "actor": {"arn": "a"}, "account": "1"}]
        self.assertEqual(CorrelationEngine().correlate(events, [])["session_chains"], [])


class TestAttackPatterns(unittest.TestCase):
    def _run(self, events):
        from services.correlation_engine import CorrelationEngine
        return CorrelationEngine().correlate(events, [])["attack_patterns"]

    def test_cryptomining_burst(self):
        events = [{"eventName": "RunInstances", "eventTime": f"2026-09-01T03:{i:02d}:00Z",
                   "actor": {"arn": "a"}, "account": "1",
                   "awsRegion": ["us-east-1", "eu-west-3", "ap-south-1"][i % 3]} for i in range(12)]
        crypto = next(x for x in self._run(events) if x["pattern"] == "cryptomining_indicator")
        self.assertEqual(crypto["severity"], "high")

    def test_snapshot_exfil(self):
        events = [{"eventName": "ModifySnapshotAttribute", "eventTime": "2026-09-01T03:00:00Z",
                   "actor": {"arn": "a"}, "account": "1"}]
        self.assertTrue(any(x["pattern"] == "snapshot_exfiltration" for x in self._run(events)))

    def test_s3_ransomware(self):
        events = [{"eventName": "DeleteObject", "eventTime": f"2026-09-01T03:{i:02d}:00Z",
                   "actor": {"arn": "a"}, "account": "1"} for i in range(25)]
        ransom = next(x for x in self._run(events) if x["pattern"] == "s3_ransomware_indicator")
        self.assertEqual(ransom["severity"], "critical")

    def test_benign_activity_no_patterns(self):
        events = [{"eventName": "GetObject", "eventTime": "2026-09-01T03:00:00Z", "actor": {"arn": "a"}, "account": "1"}]
        self.assertEqual(self._run(events), [])


class TestPreservation(unittest.TestCase):
    def test_preserve_and_verify(self):
        import tempfile
        from services.preservation import EvidencePreserver
        from services.evidence_collector import EvidenceBundle, CollectionStats
        from datetime import datetime, timezone
        b = EvidenceBundle()
        b.events = [{"eventName": "X"}]
        b.stats = CollectionStats(raw_events=1, selected=1)
        b.window_start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        b.window_end = datetime(2026, 9, 2, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            r = EvidencePreserver(out_dir=d).preserve(b, {"summary": {}}, {}, {}, case_id="TEST-1")
            self.assertEqual(r["artifact_count"], 7)
            self.assertTrue(EvidencePreserver.verify(r["path"])["intact"])
            (Path(r["path"]) / "events.json").write_text("[]")
            v2 = EvidencePreserver.verify(r["path"])
            self.assertFalse(v2["intact"])
            self.assertEqual(v2["results"]["events.json"], "MODIFIED")


class TestContainment(unittest.TestCase):
    def test_playbook_targets_escalation_actors(self):
        from services.preservation import ContainmentAdvisor
        corr = {"escalation_chains": [{"actor": "arn:aws:iam::1:user/attacker"}],
                "logging_gaps": [], "session_chains": [], "attack_patterns": []}
        pb = ContainmentAdvisor().build_playbook(corr, {"findings": []})
        self.assertIn("arn:aws:iam::1:user/attacker", pb["compromised_principals"])
        cmds = " ".join(c for s in pb["immediate"] for c in s["commands"])
        self.assertIn("update-access-key", cmds)
        self.assertIn("Inactive", cmds)

    def test_open_gap_gets_relog_step(self):
        from services.preservation import ContainmentAdvisor
        corr = {"escalation_chains": [], "session_chains": [], "attack_patterns": [],
                "logging_gaps": [{"still_open": True, "resource": "org-trail", "region": "us-east-1"}]}
        pb = ContainmentAdvisor().build_playbook(corr, {"findings": []})
        self.assertTrue(any("start-logging" in c for s in pb["immediate"] for c in s["commands"]))

    def test_role_gets_session_revocation(self):
        from services.preservation import ContainmentAdvisor
        corr = {"escalation_chains": [{"actor": "arn:aws:sts::1:assumed-role/Admin/x"}],
                "logging_gaps": [], "session_chains": [], "attack_patterns": []}
        pb = ContainmentAdvisor().build_playbook(corr, {"findings": []})
        self.assertIn("TokenIssueTime", " ".join(c for s in pb["immediate"] for c in s["commands"]))


class TestTimelineExport(unittest.TestCase):
    def test_timesketch_csv(self):
        import tempfile, csv
        from services.timeline_export import TimelineExporter
        events = [{"eventTime": "2026-09-01T03:00:00Z", "eventName": "ConsoleLogin",
                   "actor": {"arn": "arn:aws:iam::1:user/x", "type": "IAMUser"},
                   "sourceIPAddress": "1.2.3.4", "account": "1"}]
        corr = {"escalation_chains": [{"actor": "arn:aws:iam::1:user/x",
                                       "access_time": "2026-09-01T03:00:00Z", "escalation_events": []}]}
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        TimelineExporter().export(events, corr, path)
        rows = list(csv.DictReader(open(path)))
        self.assertEqual(rows[0]["timestamp_desc"], "CloudTrail Event Time")
        self.assertEqual(rows[0]["specter_tag"], "escalation_chain_start")


class TestAuditRegressions(unittest.TestCase):
    """Each maps to a finding from the pre-release audit."""

    def test_case_id_path_traversal_rejected(self):
        """AUDIT-3: case_id must not escape the evidence directory."""
        import tempfile
        from services.preservation import EvidencePreserver, _safe_case_id
        from services.evidence_collector import EvidenceBundle, CollectionStats
        b = EvidenceBundle(); b.stats = CollectionStats()
        with tempfile.TemporaryDirectory() as d:
            p = EvidencePreserver(out_dir=d)
            for bad in ("../../etc/x", "a/b", "..", "a\\b"):
                with self.assertRaises(ValueError, msg=f"should reject {bad!r}"):
                    p.preserve(b, {}, {}, {}, case_id=bad)
        self.assertEqual(_safe_case_id("IR-2026-0042"), "IR-2026-0042")
        self.assertEqual(_safe_case_id("case 42!"), "case_42")

    def test_govcloud_iam_region(self):
        """AUDIT-1: persistence hunt must use the partition's IAM endpoint."""
        src = open(Path(__file__).parent.parent / "services" / "persistence_hunter.py").read()
        self.assertIn('"us-gov-west-1" if self.broker.partition == "aws-us-gov"', src)
        self.assertNotIn('session_for(target, region="us-east-1")  # IAM is global', src)

    def test_shadow_trails_included(self):
        """AUDIT-2: multi-region trails must be visible from every region."""
        src = open(Path(__file__).parent.parent / "services" / "landscape_mapper.py").read()
        self.assertIn("includeShadowTrails=True", src)
        self.assertNotIn("includeShadowTrails=False", src)

    def test_pattern_detection_uses_counter(self):
        """AUDIT-6: no O(n^2) count() in the hot loop."""
        src = open(Path(__file__).parent.parent / "services" / "correlation_engine.py").read()
        self.assertNotIn("names.count(n)", src)
        self.assertIn("Counter(names)", src)

    def test_pattern_detection_scales(self):
        """AUDIT-6: 50k events for one actor must finish fast."""
        import time
        from services.correlation_engine import CorrelationEngine
        events = [{"eventName": ["ListBuckets", "GetObject", "DescribeInstances"][i % 3],
                   "eventTime": f"2026-09-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z",
                   "actor": {"arn": "a"}, "account": "1"} for i in range(50_000)]
        t0 = time.perf_counter()
        CorrelationEngine()._detect_attack_patterns(events)
        self.assertLess(time.perf_counter() - t0, 2.0, "pattern detection too slow at 50k events")

    def test_model_and_region_configurable(self):
        """AUDIT-4: no hardcoded model/region that commercial users can't change."""
        import specter
        s = specter.Specter.__new__(specter.Specter)
        s.model_id = "custom-model"
        s.bedrock_region = "eu-west-1"
        self.assertEqual(s.model_id, "custom-model")
        src = open(Path(__file__).parent.parent / "specter.py").read()
        self.assertIn("SPECTER_MODEL_ID", src)
        self.assertIn("--bedrock-region", src)

    def test_athena_partition_schemes(self):
        """AUDIT-15: partition predicate must not assume one table layout."""
        from services.athena_collector import _partition_predicate
        from datetime import datetime, timezone
        s, e = datetime(2026, 9, 1, tzinfo=timezone.utc), datetime(2026, 9, 3, tzinfo=timezone.utc)
        self.assertIn("CAST(year", _partition_predicate(s, e, "ymd"))
        self.assertIn("replace(timestamp", _partition_predicate(s, e, "timestamp"))
        self.assertEqual(_partition_predicate(s, e, "none"), "1=1")

    def test_secrets_never_preserved(self):
        """AUDIT-11: session tokens and secret keys must not survive _slim."""
        from services.evidence_collector import EvidenceCollector
        raw = {"eventTime": "t", "eventName": "AssumeRole",
               "userIdentity": {"arn": "a", "accessKeyId": "AKIA1"},
               "responseElements": {"credentials": {"accessKeyId": "ASIA2",
                                                    "secretAccessKey": "SECRET",
                                                    "sessionToken": "TOKEN"}}}
        out = str(EvidenceCollector._slim(raw))
        self.assertNotIn("SECRET", out)
        self.assertNotIn("TOKEN", out)
        self.assertIn("ASIA2", out)


class TestRedaction(unittest.TestCase):
    def setUp(self):
        from services.redaction import Pseudonymizer
        self.p = Pseudonymizer()

    def test_round_trip(self):
        pkg = {"actor": "arn:aws:iam::111122223333:user/svc-deploy",
               "ip": "185.220.101.47", "account": "111122223333",
               "nested": {"role": "arn:aws:iam::444455556666:role/Admin",
                          "key": "ASIAQWERTYUIOP123456"}}
        red = self.p.redact(pkg)
        self.assertNotIn("111122223333", json.dumps(red))
        self.assertNotIn("185.220.101.47", json.dumps(red))
        self.assertNotIn("svc-deploy", json.dumps(red))
        self.assertNotIn("ASIAQWERTY", json.dumps(red))
        self.assertEqual(self.p.restore(red), pkg)

    def test_consistency(self):
        """Same real value -> same token, so the model can still correlate."""
        a = self.p.redact("arn:aws:iam::111122223333:user/x did A")
        b = self.p.redact("arn:aws:iam::111122223333:user/x did B")
        self.assertEqual(a.split(" did")[0], b.split(" did")[0])

    def test_keeps_investigative_signal(self):
        pkg = {"eventName": "StopLogging", "eventTime": "2026-09-01T03:00:00Z",
               "awsRegion": "us-east-1", "attack_technique_id": "T1562.008",
               "errorCode": "AccessDenied"}
        self.assertEqual(self.p.redact(pkg), pkg)

    def test_private_ip_distinction_preserved(self):
        red = self.p.redact({"a": "10.0.0.5", "b": "8.8.8.8"})
        self.assertTrue(red["a"].startswith("IP-PRIVATE"))
        self.assertTrue(red["b"].startswith("IP-") and not red["b"].startswith("IP-PRIVATE"))

    def test_restore_longest_first(self):
        """IP-PRIVATE-1 must not be corrupted by restoring IP-1."""
        self.p.redact({"x": "10.0.0.1", "y": "1.1.1.1"})
        red = {"x": "IP-PRIVATE-1", "y": "IP-1"}
        out = self.p.restore(red)
        self.assertEqual(out, {"x": "10.0.0.1", "y": "1.1.1.1"})


class _FakeBedrock:
    """Scripted Converse responses so the agent loop can be tested offline."""
    def __init__(self, script):
        self.script = list(script)
        self.calls = []
    def converse(self, **kw):
        self.calls.append(kw)
        nxt = self.script.pop(0)
        return {"output": {"message": {"role": "assistant", "content": nxt}},
                "usage": {"inputTokens": 100, "outputTokens": 50}}


class TestAgent(unittest.TestCase):
    def _plan_schema(self):
        return {"type": "object", "properties": {"investigation_plan": {"type": "array"}}}

    def test_agent_calls_tool_then_submits(self):
        from services.agent import InvestigationAgent
        fake = _FakeBedrock([
            [{"toolUse": {"toolUseId": "t1", "name": "get_actor_timeline",
                          "input": {"actor": "arn:aws:iam::1:user/svc"}}}],
            [{"toolUse": {"toolUseId": "t2", "name": "submit_investigation_plan",
                          "input": {"investigation_plan": [{"step": 1, "action": "x"}]}}}],
        ])
        agent = InvestigationAgent(fake, "m", "sys", self._plan_schema(), max_steps=5)
        seen = {}
        agent.register("get_actor_timeline", lambda a: (seen.update(a), {"events": []})[1])
        plan = agent.run({"x": 1})
        self.assertEqual(plan["investigation_plan"][0]["step"], 1)
        self.assertEqual(seen["actor"], "arn:aws:iam::1:user/svc")
        self.assertEqual(len(agent.trace.calls), 1)
        self.assertEqual(agent.trace.calls[0].tool, "get_actor_timeline")
        self.assertFalse(agent.trace.hit_cap)
        # tool result was fed back
        self.assertIn("toolResult", json.dumps(fake.calls[1]["messages"]))

    def test_agent_respects_cap(self):
        from services.agent import InvestigationAgent
        # model keeps calling tools; cap at 2 must force submit
        script = [[{"toolUse": {"toolUseId": f"t{i}", "name": "query_events", "input": {}}}]
                  for i in range(3)]
        script.append([{"toolUse": {"toolUseId": "final", "name": "submit_investigation_plan",
                                    "input": {"investigation_plan": []}}}])
        fake = _FakeBedrock(script)
        agent = InvestigationAgent(fake, "m", "sys", self._plan_schema(), max_steps=2)
        agent.register("query_events", lambda a: {"matched": 0})
        agent.run({})
        self.assertTrue(agent.trace.hit_cap)
        self.assertTrue(agent.trace.forced_submit)
        self.assertEqual(len(agent.trace.calls), 2, "only 2 real tool calls before cap")

    def test_unknown_tool_returns_error_not_crash(self):
        from services.agent import InvestigationAgent
        fake = _FakeBedrock([
            [{"toolUse": {"toolUseId": "t1", "name": "delete_everything", "input": {}}}],
            [{"toolUse": {"toolUseId": "t2", "name": "submit_investigation_plan",
                          "input": {"investigation_plan": []}}}],
        ])
        agent = InvestigationAgent(fake, "m", "sys", self._plan_schema(), max_steps=5)
        agent.run({})
        self.assertIn("unknown tool", agent.trace.calls[0].result_summary)

    def test_no_containment_tool_exists(self):
        """The agent must not have any way to act, only to look."""
        from services.agent import build_tool_config
        names = {t["toolSpec"]["name"] for t in build_tool_config({})["tools"]}
        for forbidden in ("update_access_key", "put_user_policy", "delete", "revoke",
                          "contain", "stop_logging", "run_command"):
            self.assertFalse(any(forbidden in n for n in names), f"{forbidden} tool must not exist")

    def test_handlers_operate_on_collected_data(self):
        from services.agent import make_handlers
        from services.scoring_engine import ScoringEngine
        from services.threat_intel import ThreatIntelService
        events = [{"eventTime": "2026-09-01T03:00:00Z", "eventName": "ConsoleLogin",
                   "actor": {"arn": "arn:aws:iam::1:user/svc"}, "account": "1"},
                  {"eventTime": "2026-09-01T03:05:00Z", "eventName": "CreateAccessKey",
                   "actor": {"arn": "arn:aws:iam::1:user/svc"}, "account": "1"}]
        corr = {"session_chains": [{"session_key": "ASIAABCD...", "action_count": 3}]}
        h = make_handlers(events, corr, ThreatIntelService("mock_feeds"), ScoringEngine())
        tl = h["get_actor_timeline"]({"actor": "arn:aws:iam::1:user/svc"})
        self.assertEqual(tl["event_count"], 2)
        q = h["query_events"]({"event_names": ["CreateAccessKey"]})
        self.assertEqual(q["matched"], 1)
        sd = h["get_session_detail"]({"session_key": "ASIAABCD"})
        self.assertEqual(sd["action_count"], 3)
        self.assertEqual(h["check_principal_permissions"]({"principal_arn": "x"})["error"],
                         "no AWS access in this mode")

    def test_handlers_redact_through_pseudonymizer(self):
        """With redaction on, tool args arrive tokenized and results leave tokenized."""
        from services.agent import make_handlers
        from services.scoring_engine import ScoringEngine
        from services.threat_intel import ThreatIntelService
        from services.redaction import Pseudonymizer
        p = Pseudonymizer()
        real = "arn:aws:iam::111122223333:user/svc"
        events = [{"eventTime": "t", "eventName": "ConsoleLogin", "actor": {"arn": real},
                   "account": "111122223333", "sourceIPAddress": "185.220.101.47"}]
        tok = p.redact(real)
        h = make_handlers(events, {}, ThreatIntelService("mock_feeds"), ScoringEngine(),
                          pseudonymizer=p)
        out = h["get_actor_timeline"]({"actor": tok})
        dumped = json.dumps(out)
        self.assertNotIn("111122223333", dumped)
        self.assertNotIn("185.220.101.47", dumped)
        self.assertNotIn("svc", dumped)
        self.assertEqual(out["event_count"], 1)


class TestSovereignty(unittest.TestCase):
    """The claim: with --redact, no customer identifier reaches the model.
    This test is the proof. It runs the real synthetic package through
    redaction and asserts nothing identifying survives."""

    def test_full_package_leaks_nothing(self):
        from services.redaction import Pseudonymizer
        from services.evidence_collector import EvidenceCollector
        from services.correlation_engine import CorrelationEngine
        root = Path(__file__).parent.parent
        ct = json.load(open(root / "synthetic_data" / "cloudtrail_events.json"))
        gd = json.load(open(root / "synthetic_data" / "guardduty_findings.json"))
        slim = [EvidenceCollector._slim(e) for e in ct]
        corr = CorrelationEngine().correlate(slim, gd)
        pkg = {"correlation": corr, "event_sample": slim, "guardduty_findings": gd}
        p = Pseudonymizer()
        wire = json.dumps(p.redact(pkg))
        for real in ("123456789012", "998877665544", "185.220.101.47", "45.142.212.100",
                     "svc-deploy-prod", "svc-backup-admin", "OrgFinanceAdminRole",
                     "AKIAIOSFODNN7EXAMPLE", "finance-exports", "org-primary-trail"):
            self.assertNotIn(real, wire, f"{real} leaked to the model")
        # and the investigative signal is intact
        for keep in ("StopLogging", "CreateAccessKey", "AssumeRole", "us-east-1",
                     "2026-07-09", "escalation_chains", "logging_gaps"):
            self.assertIn(keep, wire, f"{keep} was wrongly redacted")

    def test_username_inside_session_name(self):
        """svc-deploy inside svc-deploy-session must still be tokenized."""
        from services.redaction import Pseudonymizer
        p = Pseudonymizer()
        out = p.redact({"userName": "svc-deploy", "roleSessionName": "svc-deploy-session"})
        self.assertNotIn("svc-deploy", json.dumps(out))

    def test_guardduty_free_text_without_arn(self):
        """GuardDuty names principals in prose with no ARN present."""
        from services.redaction import Pseudonymizer
        p = Pseudonymizer()
        f = {"title": "Login by principal alice-admin from Tor",
             "resource": {"accessKeyDetails": {"userName": "alice-admin"}}}
        out = json.dumps(p.redact(f))
        self.assertNotIn("alice-admin", out)
