# Memory Security

## Problem

Agentic systems increasingly use:

- vector databases
- RAG
- personal knowledge bases
- second brains
- conversation memory
- document stores

Encryption at rest protects stored data, but it does not solve the full agent exposure problem.

A typical flow is:

```text
Document
  |
  v
Embedding
  |
  v
Vector DB
  |
  v
Retrieved chunk
  |
  v
Plaintext agent context
  |
  v
LLM reasoning
```

If the model must reason over a document, relevant plaintext must eventually become readable to the model.

## Brumm Goal

Brumm should provide **controlled disclosure**, not pretend that plaintext can be eliminated from all knowledge workflows.

The goal is:

> Give the agent the minimum information necessary for the task and prevent unauthorized disclosure or exfiltration.

## Memory Classification

Example classification:

```text
PUBLIC
PERSONAL
PRIVATE
SENSITIVE
SECRET
```

Policies can then control retrieval.

```yaml
agent: coding-agent

memory:
  public: allow
  personal: allow
  private: review
  sensitive: deny
  secret: deny
```

## Retrieval Filtering

The vector database should not be the final authorization layer.

```text
Agent
  |
  v
Brumm
  |
  +-- identity
  +-- task
  +-- policy
  |
  v
Vector DB
  |
  v
filtered retrieval
  |
  v
Agent
```

## Secret Detection

Retrieved documents may accidentally contain:

- API keys
- passwords
- tokens
- private keys
- connection strings
- PII

Brumm should scan retrieved content before passing it to the agent.

Example:

```text
Document:
"Production deployment requires two approvals.

AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=..."

Brumm:
"Production deployment requires two approvals.

[SECRET REDACTED]"
```

## Memory Provenance

A memory system should retain metadata such as:

- source
- owner
- classification
- timestamp
- origin
- sensitivity
- retention
- authorization requirements

This helps answer:

> Why did this memory reach the agent?

## Encryption

Possible architecture:

```text
Memory payload
     |
     v
Encrypted storage

Embedding / searchable metadata
     |
     v
Vector DB

Retrieval
     |
     v
Brumm authorization
     |
     v
Decrypt authorized payload
     |
     v
Agent context
```

Important limitation:

Normal semantic search over strongly encrypted content is non-trivial and may require trade-offs.

Brumm should not claim "encrypted vector search" without specifying the cryptographic construction and its security properties.

## Output Boundary

Memory protection is incomplete if the agent can simply send the retrieved content elsewhere.

Therefore:

```text
Memory
  |
  v
Agent
  |
  v
Outbound tool
  |
  v
Brumm output guard
  |
  +-- allow
  +-- redact
  +-- block
  +-- approval
```

## Principle

> The agent may read what it needs to reason, but reading does not automatically imply permission to export, modify, or redistribute it.
