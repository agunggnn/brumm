# Brumm Vision

## From Secret Protection to Agentic Safety

Brumm starts from a simple problem:

> How can an AI agent use credentials without unnecessarily exposing credentials to the agent?

That problem naturally expands.

As agents become able to read private knowledge, call tools, modify infrastructure, and execute autonomous workflows, credentials are only one part of the security boundary.

An agent can be:

- authorized
- technically capable
- non-malicious
- honest about what it is doing

and still cause a catastrophic incident because its interpretation of an instruction is wrong.

Example:

```text
Human:
"Clean up old storage."

Agent:
"I found 700 GB that appears unused."

Agent:
DELETE 700 GB

Result:
Data loss.
```

The agent may not be malicious. The authorization itself was too broad.

## Brumm

> **Brumm is a security boundary for agentic systems.**

Brumm sits between an agent and sensitive capabilities.

It can protect:

- secrets
- credentials
- private memory
- documents
- vector databases
- APIs
- MCP tools
- cloud infrastructure
- Kubernetes
- destructive operations
- outbound data

## Core Principle

> Give an agent enough authority to accomplish its objective, but not enough authority to accidentally destroy everything.

## Three Security Problems

### 1. Secret exposure

The agent should not need to possess a credential merely to use a capability.

### 2. Information exposure

The agent should receive only the knowledge required for the current task.

### 3. Capability exposure

The agent should not receive unlimited authority when a constrained capability is sufficient.

## Controlled Plaintext

Brumm cannot make knowledge invisible to a model that must reason over that knowledge.

If an agent needs to understand a document, relevant content eventually has to be available to the model.

Therefore the goal is not:

> "No plaintext ever exists."

The goal is:

> "Plaintext disclosure is minimized, scoped, controlled, and prevented from escaping its authorized boundary."

## Long-Term Model

```text
                    AGENT
                      |
                      v
               +-------------+
               |        BRUMM        |
               |-------------|
               | Identity    |
               | Policy      |
               | Memory      |
               | Secrets     |
               | Validation  |
               | Risk        |
               | Audit       |
               +------+------+
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Secrets      Memory      Actions
       / Vault      / RAG       / Tools
```

## Design Principles

1. Least authority
2. Minimum disclosure
3. Bounded blast radius
4. Prefer reversible operations
5. Progressive autonomy
6. No blind trust
7. Explicit auditability
8. Fail closed for critical operations
9. Integrate rather than replace existing security systems
10. Do not make unsupported security claims
