# Capability Model

## Objective

Hetzer should explore capability-based authorization for agentic execution.

A capability represents a bounded authority.

Conceptually:

```yaml
capability:
  subject: agent-123
  action: delete
  resource: backup-prod/*
  constraints:
    max_size: 50GB
    object_age: ">90d"
  expires: 10m
  approval: false
```

## Why Capabilities

A broad identity permission such as:

```text
delete:*
```

does not express the context of a particular task.

A capability can encode:

- target
- action
- conditions
- expiry
- limits
- delegation
- approval

## Capability Lifecycle

```text
request
  |
  v
evaluate
  |
  v
issue
  |
  v
use
  |
  v
expire / revoke
```

## Capability vs Credential

A credential proves or enables access.

A capability describes a particular authorized operation.

Hetzer should investigate architectures where the agent receives a capability reference rather than a long-lived infrastructure credential.

## Security Questions

The implementation must address:

- capability forgery
- replay
- theft
- delegation
- revocation
- expiry
- confused deputy attacks
- privilege escalation
- resource substitution
- race conditions
- policy changes during execution

## Important

This document describes a design direction.

A capability mechanism must undergo security review before being treated as a security guarantee.
