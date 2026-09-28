# Agentic Safety

## The Honest Mistake Problem

A security system must defend against more than malicious agents.

An agent can honestly execute an incorrect plan.

Example:

```text
User:
"Free up disk space."

Agent:
Finds 700 GB of apparently unused data.

Agent:
Deletes it.

Agent:
Reports:
"I completed the cleanup."
```

The agent may have followed its reasoning correctly.

The failure is that the system gave the agent an unnecessarily large destructive capability.

## Brumm's Role

Brumm should place a safety boundary around consequential actions.

```text
Agent
  |
  | delete 700GB
  v
Brumm
  |
  +-- identify target
  +-- classify resource
  +-- estimate blast radius
  +-- check reversibility
  +-- evaluate policy
  +-- enforce limit
  |
  +-- DENY
  +-- REDUCE SCOPE
  +-- REQUIRE APPROVAL
  +-- EXECUTE
```

## Blast Radius

Blast radius should become a first-class security concept.

Potential factors:

- number of resources
- amount of data
- production vs non-production
- number of users affected
- reversibility
- backup availability
- privilege level
- network exposure
- external side effects

Example:

```text
DELETE

Target: production storage
Size: 700 GB
Reversible: no
Backup: unknown
Environment: production

Risk: critical
Action: require approval
```

## Safer Transformations

Brumm should not always simply block.

It can transform unsafe intent into safer execution.

```text
delete
  |
  v
snapshot
  |
  v
dry-run
  |
  v
quarantine
  |
  v
verify
  |
  v
delete
```

## Limits

Policies should support limits such as:

```yaml
max_size: 50GB
max_objects: 1000
max_resources: 10
environment: non-production
```

## Transaction Thinking

Where possible, agent operations should have:

- preview
- precondition
- execution
- verification
- rollback

This is especially important for destructive infrastructure operations.

## Human Approval

Approval should be risk-based.

The system should avoid turning every action into a confirmation dialog.

Good candidates for approval:

- irreversible production deletion
- security policy changes
- credential revocation
- destructive database operations
- large-scale external communication
- high-volume data export

## Safety Goal

> Prevent catastrophic consequences from ordinary agent reasoning errors without unnecessarily destroying agent autonomy.
