# JEV — Agentic Execution Model

## Status

**Research / Architecture Concept**

JEV is a proposed execution model for Hetzer.

The term JEV should not currently be treated as a standardized industry term. Its exact formal definition, acronym expansion, and cryptographic mechanism remain open design questions.

## Problem

Traditional automation commonly relies on bearer credentials:

```text
Token
  |
  v
Permission
  |
  v
API
```

Possession of the credential can provide broad authority.

For an autonomous agent, that creates a mismatch:

```text
Agent reasoning error
        +
Broad credential
        =
Potentially large blast radius
```

## JEV Concept

JEV explores replacing broad static authority with contextual, constrained capabilities.

```text
Intent
  +
Identity
  +
Context
  +
Policy
  +
Risk
  +
Resource
  |
  v
Dynamic Capability
  |
  v
Constrained Execution
```

## What JEV Is Trying to Achieve

A capability should answer:

- who requested the action?
- what is the intended objective?
- what resource is targeted?
- what operation is allowed?
- under what conditions?
- for how long?
- what limits apply?
- is approval required?
- can the action be revoked?
- can the result be rolled back?

## Example

Instead of:

```text
Agent -> AWS admin credential
```

JEV could conceptually produce:

```yaml
capability:
  action: delete
  resource: backup-prod/*
  conditions:
    object_age: ">90d"
    max_total_size: 50GB
    protected_prefixes:
      - snapshots/
      - disaster-recovery/
  expires: 10m
  approval: false
```

This is a design target, not a claim about current implementation.

## "No Token" Direction

The project may investigate systems where agents do not directly possess long-lived bearer tokens.

However, this must not be interpreted as "authentication disappears."

The underlying system still needs a trustworthy mechanism to establish identity and authorize execution.

Research areas include:

- workload identity
- short-lived credentials
- capability security
- delegated authorization
- cryptographic capabilities
- attestation
- local privileged brokers
- cloud-native identity
- hardware-backed keys

## JEV and RBAC

RBAC asks:

> What can this identity do?

JEV aims to ask:

> What may this agent do right now, for this objective, against this resource, under these constraints?

JEV therefore complements rather than necessarily replaces RBAC.

## Progressive Autonomy

```text
Low risk
  -> autonomous

Medium risk
  -> constrained

High risk
  -> approval

Critical / irreversible
  -> explicit approval
```

## Research Requirements

Before JEV is presented as a security primitive, Hetzer should establish:

- precise terminology
- formal security properties
- threat model
- capability representation
- identity model
- replay resistance
- revocation model
- delegation model
- expiry semantics
- policy evaluation semantics
- audit semantics
- bypass resistance
- interoperability model
