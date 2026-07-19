# SPECTER

**Systematic Priority Engine for Cloud Threat Evidence Reconstruction**

An investigation orchestrator for cloud incident response. SPECTER takes
multi-source cloud evidence and produces a sequenced, prioritized,
MITRE ATT&CK-mapped investigation plan.

---

## The problem

Responders entering an unfamiliar cloud environment face a sequencing
problem before they face a technical one: given inconsistent logging,
incomplete visibility, and time pressure, what do you examine first, and
in what order?

In practice that question is answered by whoever is the most experienced
analyst in the room. That expertise is the scarcest and least scalable
resource on any response team, and the quality of the first hour of an
engagement often determines the quality of the whole thing.

Existing tooling does not close this gap. Posture assessment tools report
what is exposed. Detection services report what their signatures matched.
Investigation consoles answer questions an analyst already knows to ask.
None of them sequence the investigation itself.

SPECTER targets that gap specifically.

## Design principles

**Evidence-aware.** Before recommending investigative steps, the system
should account for what evidence actually exists: which log sources are
active, what the retention windows are, and where the blind spots fall.
A plan that assumes complete telemetry is not useful in a real
environment.

**ATT&CK-mapped.** Every step maps to a MITRE ATT&CK for Cloud technique
where one applies. This makes the output auditable, interpretable to any
analyst regardless of who generated it, and directly reusable in
reporting.

**Adaptive.** Findings should reshape the plan. As threads are confirmed
or ruled out, priorities shift and the sequence should change with them.
This is the intended end state; Phase 01 does not implement it.

## Repository contents

```
specter_poc.py                          Phase 01 proof of concept
synthetic_data/cloudtrail_events.json   Test evidence: CloudTrail
synthetic_data/guardduty_findings.json  Test evidence: GuardDuty
docs/dataflow.mermaid                   Target architecture diagram
```

## Phase 01: proof of concept

`specter_poc.py` establishes the core reasoning path end to end. It
loads a fixed evidence set, submits it to Claude on Amazon Bedrock with
a constrained output schema, and returns a structured investigation
plan.

The output schema is enforced through a Bedrock tool definition rather
than parsed out of free text. This keeps the result machine-consumable
by downstream components and avoids brittle output parsing.

### Prerequisites

1. An AWS account with Bedrock model access enabled for an Anthropic
   Claude model. Structured tool output requires Claude Sonnet 4.5 or
   later.
2. AWS credentials with `bedrock:InvokeModel` and `bedrock:Converse`
   permissions.
3. `boto3`:
   ```
   pip install boto3
   ```

### Configuration

Model identifiers and regional availability change. Confirm what is
enabled in the target account:

```
aws bedrock list-foundation-models --by-provider anthropic --region <region>
```

Update `MODEL_ID` and `AWS_REGION` at the top of `specter_poc.py` to
match.

### Running

```
python specter_poc.py
```

The plan prints to the console and is written to
`investigation_plan_output.json`.

## Test evidence

The `synthetic_data/` directory contains a synthetic incident: 15
CloudTrail events and 5 correlating GuardDuty findings. All values are
fabricated. No account identifiers, resource names, IP addresses, or
personnel information in these files correspond to anything real.

The scenario is a compact kill chain:

| Stage | Activity |
| --- | --- |
| Initial access | Console login without MFA from an anomalous source address |
| Discovery | Identity and role enumeration |
| Privilege escalation | Access key creation for a second principal, admin policy self-attachment |
| Defense evasion | CloudTrail logging disabled for a 13-minute window |
| Lateral movement | Cross-account role assumption |
| Collection and staging | Sensitive object reads, bundled write to an out-of-inventory bucket |

Two elements are deliberate. The **logging gap** tests whether the
system reasons about absent evidence rather than only present evidence,
which is the harder and more valuable behavior. **Lateral movement** is
included because it is both under-detected in practice and
disproportionately indicative of a capable adversary, so a plan
generator that does not prioritize it correctly is not doing its job.

## Scope and limitations

Phase 01 is a proof of concept. Known constraints, all of which are
in scope for later phases:

**No evidence windowing.** The full evidence set is loaded into a single
prompt with no filtering, time-bounding, or chunking. This is acceptable
for 15 events and will not hold at production volume, where a single
active account can generate hundreds of megabytes of CloudTrail data per
day. Production requires filtering before the model is invoked: source-
level queries where a normalized log store is available, and streaming
plus rule-based triage where one is not.

**Fixed evidence set.** Evidence is read from local files rather than
collected from a live environment. There is no discovery of what log
sources exist in the target account.

**Single-pass.** One call, one plan. No feedback loop, no
reprioritization as findings develop.

**No dynamic tool use.** Phase 01 uses Bedrock's native tool-calling to
constrain output format only. It does not implement Model Context
Protocol tooling, and the model cannot invoke collection or analysis
tools during reasoning.

## Roadmap

**Phase 02 -- Evidence Landscape Mapper.** Query the target environment
to inventory available log sources, retention windows, and coverage
gaps, and produce a forensic readiness assessment before investigation
begins. This phase also introduces the ingestion and triage pipeline
described in `docs/dataflow.mermaid`.

**Phase 03 -- Investigation Plan Generator.** Retrieval-augmented plan
generation grounded in MITRE ATT&CK for Cloud and response playbooks,
with an MCP tool suite the model can invoke during reasoning rather than
being handed a static evidence set.

**Phase 04 -- Re-orchestration loop.** Stateful sessions in which
analyst findings are fed back into the orchestrator and the plan is
regenerated, elevating or closing hypotheses as evidence develops.

## Architecture

`docs/dataflow.mermaid` diagrams the target data flow from raw log
sources through ingestion, triage, chunking, and model invocation. It
distinguishes what Phase 01 implements from what remains design work.

## Licensing and use

No license is asserted. Contact the repository owner before reuse or
redistribution.
