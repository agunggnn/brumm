# Secret Security

## The Credential Exposure Problem

AI agents often need to use credentials.

The naive architecture is:

```text
Secret
  |
  v
Agent context
  |
  v
Tool
```

This exposes secrets to:

- model context
- logs
- traces
- prompts
- tool arguments
- copied output
- memory
- debugging systems

## Zero Plaintext Objective

Brumm should aim to prevent credentials from entering agent context whenever the operation can be performed without exposing them.

```text
Agent
  |
  | secretRef: prod/aws
  v
Brumm
  |
  v
Secret Provider
  |
  v
Credential
  |
  v
Target operation
```

The agent sees:

```text
secretRef://prod/aws
```

not:

```text
AKIA...
```

## Secret Provider Agnostic

Brumm should ideally integrate with existing systems instead of replacing them.

Potential providers:

- HashiCorp Vault
- 1Password
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager
- Kubernetes Secrets
- other provider APIs

## Vault + ESO

A common Kubernetes architecture is:

```text
Vault
  |
  v
External Secrets Operator
  |
  v
Kubernetes Secret
  |
  v
Pod
```

This is primarily secret distribution.

Brumm solves a different boundary:

```text
Secret Provider
  |
  v
Brumm
  |
  v
Agent / Tool
```

The distinction should remain explicit.

## Absolute Zero Plaintext

Do not claim that plaintext never exists anywhere.

A credential must be available in usable form at some point for a system to authenticate.

The defensible goal is:

> Minimize and prevent unnecessary credential exposure to agent context, logs, tool payloads, and other uncontrolled surfaces.
