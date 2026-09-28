# Brumm Target Architecture

## Overview

Brumm should operate as an agent security control plane.

```text
                         Human
                           |
                           v
                    Agent / LLM
                           |
                     Intent / Tool
                           |
                           v
                +---------------------+
                |        BRUMM        |
                |---------------------|
                | Agent Identity      |
                | Policy Engine       |
                | JEV Engine          |
                | Secret Broker       |
                | Memory Guard        |
                | Tool Guard          |
                | Risk Engine         |
                | Approval Engine     |
                | Audit               |
                +----------+----------+
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
          Secrets        Memory        Tools
          Vault/SM       Vector DB     MCP/API
          1Password      Documents     Cloud
          AWS SM         Second Brain  Kubernetes
```

## Architectural Layers

### Agent Identity

Identifies which agent, workload, user, or session is making a request.

### Policy Engine

Determines whether the requested capability is permitted.

### JEV Engine

Research direction for deriving temporary, constrained authority from identity, intent, context, policy, and risk.

### Secret Broker

Resolves credentials without unnecessarily exposing them to the model.

### Memory Guard

Controls retrieval of private knowledge and memory.

### Tool Guard

Inspects tool requests and tool outputs.

### Risk Engine

Estimates consequences such as:

- destructive action
- production target
- data volume
- irreversibility
- privilege level
- external data transfer

### Approval Engine

Escalates operations that exceed autonomous policy.

### Audit

Records security decisions without recording secrets unnecessarily.

## Important Boundary

Brumm should not become the underlying system of record for every secret, identity, or infrastructure permission.

Existing systems can remain authoritative:

```text
Vault / 1Password / AWS Secrets Manager
                  |
                  v
                Brumm
                  |
                  v
                Agent
```

This keeps Brumm focused on the agent boundary.

## Failure Model

If Brumm cannot establish authorization for a critical operation, the default should be deny.

For lower-risk read-only operations, configurable fail-open behavior may be appropriate only when explicitly enabled.

## Trust Assumption

Brumm itself becomes part of the trusted computing base.

Therefore:

- minimize privileged code
- isolate components
- minimize plaintext lifetime
- avoid secret logging
- provide deterministic policy decisions where possible
- test policy bypasses
- document cryptographic assumptions
