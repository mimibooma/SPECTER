# SPECTER

**Systematic Priority Engine for Cloud Threat Evidence Reconstruction**

An AWS incident response tool for the first hour. Point it at an estate,
even one you've never seen, and it tells you what evidence exists, what
happened, what the attacker left behind, and what to do first.

```
python specter.py --discover --regions us-east-1,us-west-2 --report incident.md
```

Read-only. Multi-account. Runs from a central security account against the
whole Organization at once.

---

## The problem it solves

Cloud IR has a starting-line problem. Detection tools tell you something
happened. Query tools answer questions you already know to ask. Posture
tools tell you what's misconfigured. None of them answer the question a
responder actually has when they walk into fifty unfamiliar accounts at
3 a.m.: *where do I start, and in what order?*

That question usually gets answered by whoever the most experienced person
in the room happens to be, working from gut, one account at a time. That
doesn't scale, and it doesn't survive that person being asleep.

SPECTER encodes the sequencing judgment into something repeatable.

---

## What it does

**Maps the evidence landscape first.** Before collecting anything it scores
forensic readiness per account/region: is CloudTrail actually on, is it
multi-region, are data events enabled, is GuardDuty running. If a region
was never logging, SPECTER says so and plans around it instead of sending
you to look for evidence that doesn't exist. Unreachable accounts show up
as findings, not blanks.

**Reduces volume before inference.** A busy account produces hundreds of MB
of CloudTrail a day. Five deterministic tiers (time window, event allowlist,
actor scoping, deduplication, budgeted selection) cut that 95–99% before a
model sees anything. Every tier reports what it dropped. For real estates
the filtering runs as SQL in Athena or Security Lake.

**Correlates across sources and accounts.** Per-actor timelines that span
accounts. Access-then-escalation chains within a time window. Cross-account
role pivots. Logging gaps with a count of what happened inside them.
**Session chains** that link each AssumeRole to every action taken under
the resulting temp credentials, so activity traces back through role pivots
to the originating principal. Named attack patterns (cryptomining bursts,
S3 ransomware indicators, snapshot exfil, secrets harvesting) matched to
AWS CIRT casework.

**Hunts for persistence.** After a credential compromise, what did they
leave? Backdoor IAM users and keys, modified role trust policies, Lambda
functions with new triggers, EventBridge rules, SSM documents, removed MFA,
altered identity providers. Checks both the collected window and live
account state, so persistence that predates the window still gets found.

**Keeps ATT&CK, adds prioritization.** Every step maps to a MITRE ATT&CK
technique, with AWS-specific sub-techniques from the [Threat Technique
Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)
where they apply. On top of that, a four-dimension score (business impact,
threat confidence, response effort, evidence quality) answers what ATT&CK
never tries to: which of these matters most, here, now.

**Preserves evidence.** Everything collected is written to disk with SHA-256
hashes and a chain-of-custody record. Re-verifiable at any time. If this
goes to legal, you have what you need.

**Writes the report and the playbook.** A Markdown incident report with
every claim tied to cited evidence, a five-sentence executive brief, a
Timesketch-compatible timeline, and a containment playbook with the exact
CLI commands to run. SPECTER never executes containment. The analyst does.

---

## How the model is used, and what it sees

Most "AI security tools" are a chatbot wrapped around a log search. This is
the opposite. Almost all the intelligence is deterministic and testable.
Remove the model entirely (`--dry-run`) and the readiness map, correlation,
persistence hunt, containment playbook, and evidence bundle are all still
produced and still correct.

**What the model does.** One job: sequencing. It receives the correlated
package (readiness summary, filtered event sample, correlation output,
persistence findings, enrichment) and returns an ordered investigation plan
through a forced tool schema. It cannot reply in prose. Its output is then
re-scored by the deterministic scoring engine, so even the ordering is one
input among four, not the final word.

**How it connects.** The `bedrock-runtime` Converse API, using the same
assumed-role credentials as everything else. No API keys, no third-party
endpoint. The call goes to the AWS region you configure. In GovCloud it
stays in GovCloud.

**What AWS does with it.** Amazon Bedrock does not store or log prompts or
completions, does not use them to train models, and does not share them
with model providers. Model providers have no access to the accounts
Bedrock runs their models in. Traffic never leaves the AWS network. With
`--bedrock-endpoint` pointed at a PrivateLink interface endpoint, it never
touches the regional public endpoint either.

**What SPECTER does on top of that: `--redact`.** Before serialization,
every account ID, principal ARN, role ARN, IP address, access key ID,
bucket name, trail name, and bare username is replaced with a stable token.
The model reasons about `PRINCIPAL-1` and `ACCOUNT-1`. The mapping lives in
process memory only and is applied in reverse to the response. In agentic
mode, tool arguments arrive tokenized, handlers restore them to query real
data, and results are re-tokenized before going back. `tests/test_specter.py
::TestSovereignty` runs the full synthetic package through this and asserts
that nothing identifying survives.

What is not redacted, on purpose: event names, timestamps, regions, error
codes, user agents. Those carry the investigative signal and don't identify
a customer.

| Control | Provided by | Flag |
| --- | --- | --- |
| No prompt logging or retention | AWS | always |
| Not used for training | AWS | always |
| Model provider has no access | AWS | always |
| In-region, on AWS network | AWS | `--bedrock-region` |
| Off the public endpoint | AWS PrivateLink | `--bedrock-endpoint` |
| Identifiers tokenized before send | SPECTER | `--redact` |
| No model call at all | SPECTER | `--dry-run` |

---

## Agentic mode

Single-shot mode hands the model a package and takes the plan it returns.
`--agent` lets the model ask questions first.

It gets the same package plus six read-only tools: pull one actor's full
timeline, drill into an assumed-role session, filter events by name/actor/
time, list the IAM policies on a principal (blast radius), enrich one
indicator, and mark a blind spot resolved (which triggers a re-score). It
calls what it needs, reads the answers, and then submits. This is Bedrock's
native Converse tool-use loop; there is no MCP server and no agent runtime
to deploy.

Guardrails, because an agent without them is just an unbounded loop:

- Every tool is read-only. There is no containment tool. There is no
  tool that writes anywhere.
- Hard cap on tool calls (`--max-agent-steps`, default 8). The model is
  told the cap and how many it has left. At the cap it is forced to submit.
- Every call and result is recorded in `agent_trace.json` in the evidence
  bundle, hashed like everything else. An analyst can replay exactly what
  the model asked and what it was told.
- Redaction applies inside the loop. The model never sees a real
  identifier through a tool result.

```
$ python specter.py --accounts 111122223333 --agent --redact

-- MODEL ----------------------------------------------------------------
  anthropic.claude-sonnet-4-5 in us-gov-west-1  [redacted, agentic]
  Agent: 3/8 tool calls, 14,220 in / 2,105 out tokens
    1. get_actor_timeline({"actor": "PRINCIPAL-1"}) -> event_count=14
    2. get_session_detail({"session_key": "KEY-2"}) -> action_count=4
    3. check_principal_permissions({"principal_arn": "PRINCIPAL-1"}) -> kind=user
```

The `resolve_blind_spot` tool is the Phase 03 re-orchestration seam pulled
forward: the model can close a gap based on evidence it found, and the plan
reprioritizes before it's submitted.

---

## Pipeline

```
AWS Organization (N accounts, read-only role in each)
   │
   ├─ AccountBroker        STS AssumeRole · credential cache · Org discovery
   ├─ LandscapeMapper      readiness sweep, 0–100 per account/region
   ├─ EvidenceCollector    5-tier reduction · API or Athena/Security Lake
   ├─ CorrelationEngine    timelines · gaps · chains · sessions · patterns
   ├─ ThreatIntel          IOC extraction · enrichment · ATT&CK group aliases
   ├─ PersistenceHunter    event-based + live-state backdoor checks
   ├─ EvidencePreserver    hashed bundle + chain of custody
   │
   ├─ Pseudonymizer        --redact: identifiers -> tokens, mapping stays local
   ├─ Bedrock (Claude)     sequences the plan; --agent adds a read-only tool loop
   │
   ├─ ScoringEngine        4-dimension priority on ATT&CK-mapped steps
   ├─ ContainmentAdvisor   exact CLI, grouped by urgency, never executed
   └─ NarrativeGenerator   incident report · exec brief · Timesketch CSV
```

---

## Quick start

```bash
pip install -r requirements.txt

# specific accounts
python specter.py --accounts 111122223333,444455556666 --regions us-east-1

# whole Organization
python specter.py --discover --regions us-east-1,us-west-2 --window-hours 48

# GovCloud
python specter.py --discover --partition aws-us-gov --regions us-gov-west-1

# estate scale via Security Lake
python specter.py --discover \
  --athena-database security_lake \
  --athena-table amazon_security_lake_table_cloudtrail \
  --athena-output s3://athena-results/ \
  --athena-source security_lake

# full output set
python specter.py --accounts 111122223333 \
  --report incident.md --timeline timeline.csv --playbook containment.json \
  --case-id IR-2026-0042

# agentic, with identifiers tokenized before the model sees anything
python specter.py --discover --agent --redact --max-agent-steps 6

# through a PrivateLink endpoint
python specter.py --discover --bedrock-endpoint https://vpce-0abc...bedrock-runtime.us-east-1.vpce.amazonaws.com

# readiness assessment only, no model call
python specter.py --discover --dry-run

# tests
python -m unittest discover -s tests -v
```

### IAM

**In each member account**, a role (default name `SPECTERForensicsReadOnly`)
trusting the security account, with:

```
cloudtrail:LookupEvents  cloudtrail:DescribeTrails  cloudtrail:GetTrailStatus
cloudtrail:GetEventSelectors  guardduty:ListDetectors  guardduty:GetDetector
guardduty:ListFindings  guardduty:GetFindings
config:DescribeConfigurationRecorderStatus  ec2:DescribeFlowLogs
securityhub:DescribeHub
iam:ListUsers  iam:ListAccessKeys  iam:ListRoles  lambda:ListFunctions
```

The IAM/Lambda ones are for the live-state persistence hunt; skip with
`--no-live-hunt` if you'd rather not grant them. Everything is read-only.

**In the security account** where SPECTER runs:

```
sts:AssumeRole              on the member-account role ARNs
organizations:ListAccounts  only if using --discover
bedrock:InvokeModel         on the model ARN, unless --dry-run
athena:StartQueryExecution  athena:GetQueryExecution  athena:GetQueryResults
glue:GetTable  glue:GetDatabase                       only for the Athena path
s3:GetObject  s3:PutObject  on the Athena results bucket
```

### Scale notes

- `LookupEvents` is limited to 2 requests/second per account and 90 days of
  history. The default 12 workers is fine for a handful of accounts; for
  more than ~20 accounts or windows over a few days, use the Athena path.
- The live-state persistence hunt calls `ListAccessKeys` once per IAM user.
  It caps at 500 users per account and logs a warning past that; for large
  accounts use the IAM credential report instead.
- The Athena partition predicate assumes integer `year`/`month`/`day`
  columns by default. Use `--athena-partitions timestamp` for
  partition-projection tables or `none` to skip it (slower, always works).
- Set `--model` and `--bedrock-region` (or `SPECTER_MODEL_ID` /
  `SPECTER_BEDROCK_REGION`) for commercial AWS; defaults are GovCloud.

---

## What the output looks like

```
-- CORRELATION -----------------------------------------------------------
  Distinct actors:          2
  Cross-account actors:     1
  Logging gaps detected:    1 (0 still open)
  Escalation chains:        2
  Session chains:           1
  Attack patterns:          1
  Attributed groups:        APT28

-- PERSISTENCE -----------------------------------------------------------
  Findings:                 3 (2 critical/high, 0 likely automation)
    [CRITICAL] role_trust_modification: UpdateAssumeRolePolicy changes who can assume a role
    [HIGH    ] iam_backdoor: CreateAccessKey establishes or extends an IAM identity

-- CONTAINMENT (recommended, not executed) --------------------------------
  ! Disable all access keys for IAM user svc-deploy-prod
  ! Attach explicit deny-all to IAM user svc-deploy-prod
  ! Re-enable logging on org-primary-trail
  + 2 short-term step(s), see --playbook

Evidence preserved: evidence/IR-2026-0042 (manifest a3f9c21e8b44...)
```

---

## How it got here

**Phase 01** was one script: fifteen CloudTrail events into Bedrock, an
ATT&CK-mapped plan out. It proved the idea and couldn't scale past a demo.

**Between phases** I ran an experiment: point a locally-hosted model at the
Phase 02 work and see how far it got on its own. It made the right call on
ATT&CK (layer, don't replace), but it drifted from the actual asks, never
wired its code into the running system, and shipped six correctness bugs
including a composite-score formula that made "critical" unreachable. Useful
because it mapped where the boundary was.

**Phase 02** closed every gap and added the IR layer: multi-account
concurrent collection, Athena backend, correlation, session chains, attack
patterns, persistence hunting, evidence preservation, containment guidance,
and the narrative report. All eight inherited bugs are pinned by named
regression tests.

~6,000 lines, 76 tests.

---

## Design rules

- **Read-only, always.** SPECTER recommends. Humans act.
- **Deterministic core, narrow model.** If the model were removed, the
  landscape, correlation, persistence hunt, and enrichment would all still
  be correct.
- **ATT&CK stays.** Portability across teams and tools beats any private
  taxonomy.
- **Absence is evidence.** Gaps, unreachable accounts, and disabled logging
  are findings, never silently dropped.
- **Nothing hidden.** Every reduction tier is counted and reported. In
  agentic mode, every tool call is too.
- **Your data stays yours.** No prompt retention, no training, in-region,
  PrivateLink if you want it, and `--redact` so the model never sees a real
  identifier regardless.

---

## Limitations

- **Not yet run against a live estate.** Everything is unit tested and the
  pipeline is validated end-to-end on synthetic data. First production run
  is the real test. Expect to tune the event allowlist and worker count.
- **Threat feeds are synthetic.** They exercise the enrichment path but
  aren't real intel. Swap in a production feed via the `ThreatFeed`
  interface before trusting attribution.
- **Attack patterns are heuristics.** They name clusters worth checking,
  not confirmed compromises.
- **AWS only.** Scoring anticipates Azure and GCP; nothing else does yet.
- **Scoring weights are a starting point.** Tune them against real analyst
  judgment on real incidents.

---

## Layout

```
specter.py                        orchestrator + CLI
services/
  account_broker.py               multi-account STS access
  landscape_mapper.py             forensic readiness
  evidence_collector.py           5-tier reduction, API + Athena
  athena_collector.py             estate-scale SQL
  correlation_engine.py           timelines · gaps · chains · sessions · patterns
  threat_intel.py                 IOC extraction + enrichment
  persistence_hunter.py           backdoor detection, event + live state
  preservation.py                 hashed evidence bundle + containment playbook
  timeline_export.py              Timesketch / CSV / JSONL
  scoring_engine.py               4-dimension prioritization
  narrative_generator.py          report + exec brief
  redaction.py                    tokenize identifiers before the model call
  agent.py                        Converse tool-use loop with guardrails
tests/test_specter.py             76 tests
docs/PHASE02.md                   technical detail
business_context.yaml             asset criticality config
mock_feeds/                       synthetic threat feeds
synthetic_data/                   a full kill chain for testing
```

---

## What's next

Agentic mode pulled the core of Phase 03 forward: the model can now call
tools mid-investigation and re-score as it closes gaps. What remains:

- Stateful sessions across runs, so an analyst can resume an investigation
  and the agent picks up where it left off.
- More tools: Athena queries the agent composes itself (bounded, read-only),
  Config history for a resource, VPC flow log summaries.
- A read-only viewer for the readiness map, actor timeline, and live plan
  reordering. CLI-first until then.
- Calibrate scoring weights against real analyst judgment.

---

## License

MIT. See [LICENSE](LICENSE).

Independent engineering project. No warranty. Validate in your own
environment before operational use.
