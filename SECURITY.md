# Security

## Reporting a vulnerability

Open a GitHub security advisory on this repo, or email the maintainer
(address in the commit log). Please don't open a public issue for security
problems.

You'll get an acknowledgement within a few days. There's no bounty; this is
a one-person project.

## What SPECTER touches

SPECTER is read-only by design. It assumes a role in each target account and
calls only `List*`, `Describe*`, `Get*`, and `Lookup*` APIs. It never creates,
modifies, or deletes AWS resources. The containment playbook it generates is
text; nothing in it is executed.

The one write it performs is to local disk: the evidence bundle under
`evidence/<case-id>/`. That bundle contains CloudTrail records and GuardDuty
findings from the accounts you pointed it at. Treat it as sensitive. Session
tokens and secret keys are stripped before anything is written, but the
records still identify principals, IPs, and resource names.

## Model calls

The investigation plan step sends a correlated summary (not raw logs) to
Amazon Bedrock in the region you configure. If that's not acceptable for
your data, use `--dry-run`; every deterministic stage still runs and you get
the readiness map, correlation, persistence findings, containment playbook,
and evidence bundle without a model call.

## Scope

In scope: anything that lets SPECTER write to AWS, exfiltrate data it
collected, escape the evidence directory, or execute containment commands
without an operator.

Out of scope: findings the heuristics miss (they're heuristics), and
anything requiring credentials SPECTER was never granted.
