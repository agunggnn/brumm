# Hetzer Examples

## Example 1 — Credential Use

### Without Hetzer

```text
Agent
  |
  v
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
  |
  v
AWS CLI
```

The secret can enter agent context or logs.

### With Hetzer

```text
Agent
  |
  | secretRef://prod/aws
  v
Hetzer
  |
  v
AWS credential
  |
  v
AWS operation
```

The credential does not need to be returned to the model.

---

## Example 2 — Private Memory

Agent asks:

```text
"What is the architecture decision we made last month?"
```

Hetzer evaluates:

```text
identity
+
task
+
memory policy
+
retrieval
```

and returns only authorized memories.

---

## Example 3 — Secret in Document

Retrieved document:

```text
Deployment policy:
Production requires two approvals.

AWS_SECRET_ACCESS_KEY=...
```

Hetzer:

```text
Deployment policy:
Production requires two approvals.

[SECRET REDACTED]
```

---

## Example 4 — 700 GB Deletion

Agent:

```text
delete backup-prod 700GB
```

Policy:

```text
maximum autonomous deletion = 50GB
```

Hetzer:

```text
DENY

Requested: 700GB
Allowed: 50GB
Reason: blast-radius limit exceeded
```

Potential alternative:

```text
snapshot
+
dry-run
+
approval
```

---

## Example 5 — Data Exfiltration

Agent reads:

```text
private customer document
```

Then attempts:

```text
send_to_external_api(document)
```

Hetzer detects:

```text
data classification = confidential
destination = external
operation = export
```

Result:

```text
BLOCK
```

or:

```text
REQUIRE APPROVAL
```

---

## Example 6 — Safe Autonomy

Agent performs:

```text
read logs
check pod status
restart failed non-production pod
```

Policy:

```text
read = allow
non-prod restart = allow
production restart = approval
```

The agent remains useful without receiving unrestricted power.

---

## Example 7 — Tool Output Leakage

A database query returns:

```text
user_id
name
email
api_token
```

Hetzer can transform:

```text
user_id
name
email
api_token=[REDACTED]
```

before the content enters subsequent agent context.
