# Hetzer Roadmap

## Strategy

Build incrementally.

Do not attempt to replace Vault, 1Password, cloud IAM, Kubernetes RBAC, PAM, or vector databases.

Hetzer should become the security boundary connecting them to agents.

---

## Phase 0 — Foundation

- [ ] Define current architecture
- [ ] Document threat model
- [ ] Establish security terminology
- [ ] Separate implemented vs planned claims
- [ ] Build security test suite
- [ ] Establish no-secret-logging rules

---

## Phase 1 — Secret Protection

- [ ] encrypted credential store
- [ ] secret references
- [ ] secret resolution
- [ ] redaction
- [ ] Git protection
- [ ] leak detection
- [ ] canary credentials
- [ ] audit logging
- [ ] provider abstraction

Potential integrations:

- [ ] Vault
- [ ] 1Password
- [ ] AWS Secrets Manager
- [ ] Azure Key Vault
- [ ] Google Secret Manager
- [ ] Kubernetes Secrets

---

## Phase 2 — Agent and MCP Security

- [ ] MCP proxy
- [ ] agent identity
- [ ] tool allowlists
- [ ] argument inspection
- [ ] secret detection
- [ ] output sanitization
- [ ] tool-level policy
- [ ] audit trail

---

## Phase 3 — Memory Security

- [ ] encrypted memory payloads
- [ ] vector DB adapters
- [ ] memory classification
- [ ] retrieval authorization
- [ ] PII detection
- [ ] secret detection
- [ ] context minimization
- [ ] provenance
- [ ] memory audit

---

## Phase 4 — Agentic Execution Safety

- [ ] destructive action detection
- [ ] resource classification
- [ ] blast-radius estimation
- [ ] dry-run
- [ ] operation limits
- [ ] snapshot-before-delete
- [ ] reversible execution
- [ ] approval workflows
- [ ] transaction boundaries

---

## Phase 5 — JEV Research

- [ ] formal JEV definition
- [ ] identity model
- [ ] intent model
- [ ] capability representation
- [ ] dynamic capabilities
- [ ] expiry
- [ ] revocation
- [ ] delegation
- [ ] policy binding
- [ ] replay protection
- [ ] cryptographic design
- [ ] formal threat model

---

## Phase 6 — Agentic Security Platform

Target:

```text
                    Agent
                      |
                      v
                   Hetzer
                      |
       +--------------+--------------+
       |              |              |
    Secrets         Memory         Actions
       |              |              |
      Vault          RAG           Cloud
    1Password       Vector DB     Kubernetes
      AWS SM        Documents       APIs
```

## Success Criteria

Hetzer should eventually demonstrate:

### Secret scenario

Agent uses a production credential without the credential appearing in agent context.

### Memory scenario

Agent can reason over authorized private knowledge while unauthorized memory remains inaccessible.

### Safety scenario

Agent requests deletion of 700 GB when policy allows 50 GB.

Hetzer prevents the unsafe operation or escalates it.

### Exfiltration scenario

Agent reads confidential data and attempts to send it externally.

Hetzer detects and blocks or requires approval.

### Autonomy scenario

Low-risk tasks execute without unnecessary human interaction.

High-risk tasks receive stronger controls.

## Non-Goals

Hetzer is not intended to become:

- every secret manager
- every IAM system
- every PAM system
- every SIEM
- a generic LLM firewall
- a system that simply blocks autonomous behavior
- an autonomous decision maker

## Guiding Principle

> Don't remove the agent's capability. Constrain the consequences of its mistakes.
