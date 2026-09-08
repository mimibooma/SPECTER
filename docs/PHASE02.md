# SPECTER Phase 02 — Technical Notes

## What Phase 02 adds

Phase 01 proved the reasoning path: hand a model cloud evidence, get back
an ATT&CK-mapped investigation plan. It ran against a fixed 15-event file
in one account.

Phase 02 makes it work against a real estate:

| Capability | Phase 01 | Phase 02 |
| --- | --- | --- |
| Accounts | 1, implicit | N, concurrent, via assumed role |
| Regions | 1 | N per account, concurrent |
| Evidence source | static JSON file | live CloudTrail + GuardDuty |
| Volume handling | none (whole file into prompt) | five-tier reduction pipeline |
| Evidence awareness | none | forensic readiness scoring per account/region |
| Correlation | none | actor timelines, logging gaps, escalation chains, pivots |
| Threat intel | none | IOC extraction + feed enrichment |
| Prioritization | model's own ordering | four-dimension weighted scoring |

---

## Architecture

```
AccountBroker          STS AssumeRole, credential cache, Organizations discovery
      |
LandscapeMapper        concurrent readiness sweep -> what evidence exists
      |
EvidenceCollector      concurrent collection -> five-tier reduction
      |
CorrelationEngine      actor timelines, gaps, chains, cross-account pivots
      |
ThreatIntelService     IOC extraction, feed enrichment, ATT&CK group attribution
      |
   [Bedrock]           model reasons over the correlated package, not raw logs
      |
ScoringEngine          business-context prioritization of ATT&CK-mapped steps
```

Everything before the model call is deterministic. That matters for cost,
for latency, and for defensibility: an analyst can audit exactly what was
collected and why, independent of anything the model decided.

---

## The volume problem and how it is solved

A single active AWS account can emit hundreds of megabytes of CloudTrail
per day. No context window absorbs that. Reduction is tiered, cheapest
filter first:

| Tier | Mechanism | Typical reduction |
| --- | --- | --- |
| 1 | Time window bound at the API | scoped to incident |
| 2 | Event-name allowlist (7 groups, ~120 security-relevant calls) | 90–98% |
| 3 | Actor scoping (optional) | varies |
| 4 | Deduplication of repeated identical calls | 30–70% of remainder |
| 5 | Budgeted selection by signal rank | to fit token budget |

Two properties matter more than the ratio:

**Nothing is hidden.** `CollectionStats` reports raw count, count after
each tier, what was dropped by budget, and the resulting reduction ratio.
An analyst can always answer "what did the tool decide not to show me?"

**Deduplication preserves shape.** A run of 500 identical `ListBuckets`
calls collapses to first and last, annotated with `repeatCount: 500`. The
timeline stays readable and the volume signal survives.

### When to use Athena instead

`LookupEvents` permits one attribute filter per call and is rate-limited,
so it suits targeted windows rather than estate-wide sweeps. For large
estates the intended path is Athena or Security Lake against the trail's
S3 bucket, pushing tiers 1–3 into SQL. The collector interface is
unchanged; only the fetch implementation swaps. Note that CloudTrail Lake
closed to new customers on 31 May 2026, so Security Lake is the current
ingestion path for new deployments.

---

## Forensic readiness scoring

The landscape mapper scores each account/region 0–100 before collection:

| Signal | Weight | Why |
| --- | --- | --- |
| Active CloudTrail trail | 35 | without it there is no investigation |
| GuardDuty enabled | 20 | managed detection + attack-sequence correlation |
| Multi-region trail | 10 | activity outside monitored regions is invisible |
| S3/Lambda data events | 10 | object-level access, exfiltration evidence |
| AWS Config recording | 8 | configuration history for timeline reconstruction |
| VPC flow logs | 7 | corroborates lateral movement and exfil volume |
| Log file validation | 5 | evidentiary integrity |
| Security Hub | 5 | aggregation |

Bands: **strong** 80+, **adequate** 60–79, **degraded** 35–59,
**severely_limited** below 35, **no_access** where the role could not be
assumed.

An account that cannot be reached appears in output with
`reachable: false` rather than being dropped. "We could not see this
account" is a finding the analyst and the model both need.

---

## Design assumptions

These are choices, not facts. Each can be revisited.

1. **SPECTER runs from a central security tooling account** and reaches
   member accounts by assuming a role. It does not run inside accounts
   under investigation. This follows the AWS delegated security account
   pattern.

2. **A consistently-named read-only IR role exists** in each in-scope
   account, default `SPECTERForensicsReadOnly`. Consistent naming is what
   makes fan-out tractable. Per-account overrides are supported but are
   the exception.

3. **Organizations discovery is optional.** Many IR engagements run
   against accounts the responder does not own, so discovery failure
   falls back to an explicit account list rather than erroring.

4. **GuardDuty Extended Threat Detection is authoritative where present.**
   GuardDuty already performs multi-stage correlation with ATT&CK tactics
   attached. Attack-sequence findings are pulled out separately, exempted
   from budget pressure, and the prompt instructs the model to build on
   them rather than re-derive them.

5. **Read-only throughout.** No containment, no remediation, no writes.
   SPECTER recommends; humans act.

6. **ATT&CK is kept, not replaced.** Scoring layers on top. Every step
   retains its technique ID and tactic, so output stays joinable against
   ATT&CK Navigator and interpretable by any analyst.

---

## Why ATT&CK was kept

A locally invented taxonomy would break the property that makes ATT&CK
valuable: portability. An analyst from another team, a partner
organization, or a vendor tool can read `T1562.008` and know exactly what
is meant. That network effect is the point, and it cannot be replicated
by a better-designed private scheme.

What ATT&CK on purpose does *not* provide is prioritization. It says
what a technique is, not whether investigating it matters more than
investigating another one in your environment. That gap is where the
scoring engine sits, and it is additive rather than competitive.

---

## Prioritization model

Four weighted dimensions producing a 0–10 composite:

| Dimension | Weight | Inputs |
| --- | --- | --- |
| Business impact | 40% | asset tier, blast radius, data sensitivity, SLA risk |
| Threat confidence | 30% | feed confidence, actor attribution, IOC corroboration |
| Response effort | 20% | effort level 1–5, inverted, analyst count |
| Evidence quality | 10% | completeness, reliability, confidence, minus blind spots |

Bands: critical ≥7.5, high ≥5.0, medium ≥2.5, low below.

Actor attribution weights by sophistication tier: state-nexus +2.0,
criminal +1.5, unknown +0.5. Group names resolve through an ATT&CK G-ID
alias table, so `APT29`, `Cozy Bear`, and `Midnight Blizzard` all enrich
identically.

---

## Defects fixed from the prior draft

Each has a regression test in `tests/test_specter.py`.

| # | Defect | Effect | Test |
| --- | --- | --- | --- |
| 1 | Composite divided by 10 after weighting | max achievable ~1.0 against a 7.5 threshold; nothing could ever be critical | `test_composite_score_reaches_critical_band` |
| 2 | Evidence quality summed three 0–10 values then clamped | anything above ~33% scored a perfect 10 | `test_evidence_quality_not_saturated` |
| 3 | Response effort rose as analysts were added | more resources made a task look harder | `test_more_analysts_reduces_effort` |
| 4 | Critical path sorted ascending on the overdue flag | non-overdue items surfaced above overdue ones | `test_critical_path_puts_overdue_first` |
| 5 | Five hardcoded threat group names, no aliases | APT29 matched, Cozy Bear did not, same group | `test_threat_group_aliases_resolve` |
| 6 | Threat actors tagged with T-prefixed IDs | actors labelled as techniques; output not joinable against ATT&CK | `test_group_ids_use_g_prefix` |
| 7 | Feed parser expected commas; feeds are pipe-delimited | every enrichment lookup silently missed | verified in end-to-end run |
| 8 | Scoring engine never imported by anything | no behavioural change from any of it | wired in `specter.py` |

Additions beyond the fixes: RFC1918 addresses are excluded from IOC
extraction, AWS service domains are denylisted, and enrichment degrades
explicitly (with a flag in output) rather than failing silently when
feeds are absent.

---

## The IR layer

Everything above is analysis. These turn it into incident response.

**Persistence hunting** (`persistence_hunter.py`). Nine mechanisms, each
mapped to an ATT&CK technique with a link into the AWS Threat Technique
Catalog. Event-based checks scan the collected window; live-state checks
enumerate IAM users, keys, role trust policies, and Lambda functions for
artifacts that predate the window. Principals that look like deploy
pipelines get downgraded unless they're already suspects.

**Session chains** (`correlation_engine.py`). AssumeRole responses carry the
minted temp key; later calls carry it in `userIdentity.accessKeyId`. Join
on the key and role pivots stop breaking the trail.

**Attack patterns** (`correlation_engine.py`). Cryptomining bursts, S3
ransomware indicators, snapshot exfil, discovery bursts, secrets harvesting,
resource exposure. Heuristics named after AWS CIRT casework patterns.

**Evidence preservation** (`preservation.py`). Every artifact written with a
SHA-256, a manifest hashed over the artifact hashes, and a chain-of-custody
text file. `EvidencePreserver.verify()` re-hashes and reports drift.

**Containment playbook** (`preservation.py`). Exact `aws` CLI for each
compromised principal (disable keys, deny-all policy, revoke role sessions
via `aws:TokenIssueTime`), re-enabling disabled trails, and reviewing
persistence artifacts. Grouped immediate / short-term / verify. Never
executed by the tool.

**Timeline export** (`timeline_export.py`). Timesketch CSV with a
`specter_tag` column marking events that appear in correlation findings.

---

## Model boundary and data handling

The model call is the only step that sends anything outside the process.
Everything that reaches it is in the `package` dict built by
`Specter._build_package`. What is in it:

- evidence landscape summary (counts, scores, gap frequencies)
- collection stats (counts only)
- correlation output (actor ARNs, IPs, timestamps, event names, session
  keys, pattern names)
- threat intel enrichment (IOCs, group names, confidence)
- persistence findings (mechanism, actor, resource, detail)
- event sample (slimmed CloudTrail: time, name, source, actor, IP, account,
  region, request parameters pruned to 260 chars, MFA flag)
- GuardDuty finding summaries (type, severity, title, account, region)

What is not in it: raw CloudTrail records, response elements beyond the
AssumeRole key ID, secrets, session tokens, full request bodies.

With `--redact`, `Pseudonymizer.redact()` runs over the package before
`json.dumps`. It tokenizes in this order: ARNs (harvesting bare names from
them), access key IDs, 12-digit account IDs, IPv4 (preserving the
private/public distinction), bucket names in known field positions, and
then a second pass over bare names harvested from `userName`, `roleName`,
`trailName`, `functionName`, `sessionName`, and `name` fields. The reverse
mapping is applied to the model's response before scoring.

`tests/test_specter.py::TestSovereignty::test_full_package_leaks_nothing`
is the regression test. It runs the real synthetic package through and
asserts ten known identifiers are absent from the wire form.

Bedrock side: no prompt/completion logging or retention, not used for
training, model providers have no access to Bedrock's deployment accounts,
traffic stays in-region on the AWS network. `--bedrock-endpoint` routes
through a PrivateLink interface endpoint so it never touches the public
regional endpoint. FedRAMP High and DoD SRG in GovCloud; FedRAMP Moderate,
SOC 1/2/3, ISO 27001/27017/27018, HIPAA-eligible in commercial regions.

## Agentic mode

`services/agent.py`. Uses Bedrock Converse's native multi-turn tool use:
the model returns `toolUse` blocks, SPECTER executes the handlers, appends
`toolResult` blocks, and calls Converse again. Loop ends when the model
calls `submit_investigation_plan` or the step cap forces it.

Tools and what they read:

| Tool | Reads | AWS call? |
| --- | --- | --- |
| `get_actor_timeline` | collected events | no |
| `get_session_detail` | correlation output | no |
| `query_events` | collected events | no |
| `check_principal_permissions` | IAM | yes, read-only |
| `lookup_indicator` | threat feeds | no |
| `resolve_blind_spot` | plan steps | no |

`check_principal_permissions` is the only one that makes a live call. It
uses the same assumed-role session as collection and only calls
`ListAttachedUserPolicies`, `ListUserPolicies`, `ListGroupsForUser`,
`ListAttachedRolePolicies`, `ListRolePolicies`.

Each tool result is capped at 12,000 characters before going back to the
model. The trace records step number, tool, args, a result summary, and
byte count. It's written to `agent_trace.json` in the evidence bundle
after the model phase completes.

---

## Running it

```bash
# Explicit accounts
python specter.py --accounts 111122223333,444455556666 \
                  --regions us-east-1,us-west-2 --window-hours 48

# Organizations discovery
python specter.py --discover --regions us-east-1

# GovCloud
python specter.py --discover --partition aws-us-gov --regions us-gov-west-1

# Collect and correlate without paying for inference
python specter.py --accounts 111122223333 --dry-run

# Tests
python -m unittest discover -s tests -v
```

Required IAM in each member account (read-only):
`cloudtrail:LookupEvents`, `cloudtrail:DescribeTrails`,
`cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`,
`guardduty:ListDetectors`, `guardduty:GetDetector`,
`guardduty:ListFindings`, `guardduty:GetFindings`,
`config:DescribeConfigurationRecorderStatus`, `ec2:DescribeFlowLogs`,
`securityhub:DescribeHub`.

---

## Known limitations

**Untested against live AWS.** Every deterministic component is unit
tested and the full pipeline is validated end-to-end against synthetic
data, but no component has run against a real multi-account estate. First
live execution is the real test. Expect to tune the event allowlist and
worker count against actual volume.

**LookupEvents is the throughput ceiling.** Estate-wide sweeps will hit
rate limits before they hit anything else. The Athena path exists for
this reason and is the next implementation priority.

**Mock feeds are synthetic.** They exercise the enrichment path
correctly, but attribution from them is not real intelligence. Swap in a
production feed via the `ThreatFeed` interface before any operational
conclusion rests on attribution.

**No Azure or GCP.** The architecture anticipates them (provider
multipliers exist in scoring) but only AWS is implemented.

**Scoring weights are unvalidated.** The 40/30/20/10 split is a
reasonable starting point, not an empirically derived one. It should be
tuned against real analyst judgment on real incidents.

---

## Next: Phase 03

The re-scoring hook (`ScoringEngine.rescore_with_new_evidence`) is the
seam the re-orchestration loop plugs into: as an analyst resolves blind
spots, evidence quality rises and the plan reorders itself. Making that
stateful across a session, with MCP tools the model can invoke mid-
investigation rather than receiving a fixed package, is Phase 03.
