# MCP and Tool Security

## Problem

An agent can be safe internally but dangerous through its tools.

Example:

```text
Agent
  |
  +-- kubectl delete
  +-- AWS API
  +-- SSH
  +-- database
  +-- Slack
  +-- filesystem
```

The tool boundary therefore becomes a critical enforcement point.

## Brumm MCP Proxy

Target architecture:

```text
Agent
  |
  v
Brumm MCP Proxy
  |
  +-- identity
  +-- policy
  +-- argument inspection
  +-- secret protection
  +-- risk evaluation
  +-- output inspection
  |
  v
MCP Server
```

## Tool Input Guard

Inspect:

- command
- arguments
- resource
- destination
- data volume
- secrets
- destructive operations

Example:

```text
delete_volume("prod-data")
```

can trigger:

```text
production resource
+
destructive action
+
irreversible
=
approval required
```

## Tool Output Guard

Inspect outputs for:

- credentials
- tokens
- private keys
- PII
- confidential data
- sensitive infrastructure details

## Tool-to-Tool Exfiltration

A dangerous pattern is:

```text
Read private document
       |
       v
Agent
       |
       v
send_to_external_service()
```

Brumm should evaluate the outbound operation independently.

Reading data does not imply permission to export it.

## Tool Identity

Policies should be able to distinguish:

```text
read_database
delete_database
export_database
send_email
post_slack
execute_shell
```

rather than treating the entire tool as one permission.

## Dry Run

Destructive tools should support preview where possible.

```text
Agent request
   |
   v
Brumm
   |
   v
dry-run
   |
   v
impact summary
   |
   v
allow / constrain / approve
```
