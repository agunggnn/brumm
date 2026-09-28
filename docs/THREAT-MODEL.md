# Hetzer Threat Model

## Scope

Hetzer protects agentic workflows against:

1. accidental agent mistakes
2. over-privileged agents
3. secret exposure
4. unauthorized memory retrieval
5. tool misuse
6. data exfiltration
7. prompt/tool manipulation
8. confused-deputy behavior
9. compromised agent processes

## Primary Threat

### Honest but Wrong Agent

The agent follows its reasoning but performs an unsafe action.

Example:

```text
"Clean storage"
       |
       v
Delete 700GB
```

Mitigation:

- scoped capabilities
- blast-radius limits
- destructive action detection
- dry-run
- snapshots
- approval

## Secret Leakage

Threat:

```text
Agent receives AWS secret
       |
       v
logs / context / tool output
```

Mitigation:

- secret references
- brokered credentials
- redaction
- output scanning
- audit without secret values

## Memory Leakage

Threat:

```text
Agent retrieves private memory
       |
       v
external tool
```

Mitigation:

- memory classification
- retrieval authorization
- output DLP
- outbound policy

## Prompt Injection

Threat:

A document or tool output attempts to manipulate the agent into bypassing policy.

Important principle:

> Agent instructions are not security policy.

Hetzer must enforce security controls outside the model's own reasoning.

## Confused Deputy

Threat:

An agent uses a legitimate capability for a different purpose than intended.

Mitigation:

- task/context binding
- capability scope
- resource constraints
- outbound controls
- audit

## Failures

Potential failures include:

- policy bypass
- stale policy
- race conditions
- incomplete resource classification
- inaccurate blast-radius estimation
- compromised Hetzer
- compromised underlying identity provider

Hetzer should explicitly document which threats it can and cannot mitigate.

## Security Boundary

Hetzer itself is trusted infrastructure.

A compromised Hetzer process may bypass protections.

Therefore hardening Hetzer is part of the security model.
