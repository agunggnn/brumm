# Policy Engine

## Purpose

The policy engine is the control point that decides whether an agent may access information or perform an action.

## Policy Inputs

A policy decision may use:

```text
Agent identity
User identity
Intent
Tool
Action
Resource
Environment
Time
Data classification
Risk
Blast radius
Approval state
```

## Example

```yaml
agent: cleanup-agent

rule:
  action: delete
  resource: backup-prod/*

conditions:
  environment: production
  object_age: ">90d"
  max_total_size: 50GB
  require_snapshot: true
  require_approval_above: 50GB
```

## Decision Model

```text
REQUEST
   |
   v
IDENTIFY
   |
   v
CLASSIFY
   |
   v
EVALUATE
   |
   +---- DENY
   |
   +---- ALLOW
   |
   +---- CONSTRAIN
   |
   +---- APPROVAL
```

## Policy Should Be Deterministic Where Possible

Security-critical authorization should not depend solely on an LLM deciding whether an action "feels safe."

LLMs may assist with:

- intent extraction
- summarization
- risk explanation

But final enforcement should rely on deterministic rules and verifiable state wherever practical.

## Policy Precedence

A possible model:

```text
explicit deny
    >
critical resource protection
    >
approval requirement
    >
scope limits
    >
allow
```

The exact precedence should be formally specified before implementation.

## Policy Simulation

A future CLI should support:

```text
brumm policy test \
  --agent cleanup-agent \
  --action delete \
  --resource backup-prod \
  --size 700GB
```

Output:

```text
Decision: DENY

Reasons:
- production resource
- irreversible operation
- requested size exceeds 50GB
- snapshot requirement not satisfied
```

This makes policy behavior testable and reviewable.
