# Open Questions

This document records unresolved technical questions. These should be answered before turning design concepts into security claims.

## JEV

- What exactly does JEV stand for?
- Is JEV a protocol, execution engine, authorization model, or architecture?
- Can its security properties be formally described?
- How does an agent authenticate?
- How are capabilities represented?
- How are capabilities revoked?
- How are capabilities bound to intent?
- How is replay prevented?
- How is delegation handled?
- How does JEV interact with cloud IAM?
- Can JEV work without bearer tokens?
- What cryptographic primitives are required?

## Agent Identity

- How does Brumm uniquely identify an agent?
- How should multiple agents delegate work?
- How should human identity bind to agent identity?
- How should workload identity be handled?

## Policy

- Should policies use YAML, JSON, Rego, or another model?
- How should conflicting policies be resolved?
- How should policy changes affect already-issued capabilities?
- How should policy decisions be tested?

## Risk

- How should blast radius be estimated?
- Which values can be deterministic?
- Where can an LLM assist?
- How do we avoid trusting the LLM to judge its own safety?

## Memory

- Which vector databases should be supported?
- What exactly is encrypted?
- Can embeddings reveal sensitive information?
- How should encrypted memory be searched?
- How should memory provenance work?
- How should retention and deletion work?

## Secrets

- How should secret providers be abstracted?
- How can Brumm prevent secret values from reaching model context?
- How should credentials be injected into child processes?
- How should secret rotation work?

## MCP

- How should MCP tools be classified?
- How should tool arguments be inspected?
- How should tool output be inspected?
- How should malicious MCP servers be handled?

## Recovery

- Can Brumm automatically create snapshots?
- Which infrastructure operations can be made transactional?
- How should rollback be represented?
- Can Brumm automatically reduce destructive operations to a safe scope?

## Security

- What is the exact trusted computing base?
- What happens if Brumm itself is compromised?
- How do we prevent policy bypass?
- How do we protect the audit log?
- What should be independently audited or penetration tested?

## Product

- Should Brumm remain local-first?
- Should there be an enterprise control plane?
- What belongs in the open-source core?
- What is the minimum compelling product before expanding into JEV?
