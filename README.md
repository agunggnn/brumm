# Brumm 🐻🛡️
> *Also known as **Brummbär** // The "Denial Smart Boss" for Autonomous AI Agents*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Research_&_Architecture-orange.svg)](#)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-Hetzer_&_Jagdpanzer-purple.svg)](#)

**Brumm** is an agentic governance and constraint engine that prevents catastrophic execution errors by autonomous AI agents. Acting as the senior, curmudgeonly "Denial Leader" in your workflow, Brumm challenges flawed agent assumptions, computes blast radiuses, and replaces destructive actions with minimal, reversible capabilities (JEV).

---

## 💡 The Problem: The "Honest Mistake"

Most agent security frameworks defend against malicious prompt injection. But in practice, **the most dangerous agent is often authorized, non-malicious, and honest**:

```text
User:   "Free up disk space."
Agent:  Finds 700 GB of apparently unused data in production.
Agent:  Executes `rm -rf /data/*`.
Agent:  Reports "Cleanup completed successfully!"
```

The agent followed its internal reasoning correctly. The failure was that the system granted it unconstrained, irreversible capability.

---

## 🛡️ Brumm's Role: The Smart Denial Leader

Brumm does not just say a blind, frustrating "NO". It applies **Constructive Refusal**:

```text
Agent Action Request (e.g. DELETE 700GB / Request AWS Admin Key)
      |
      v
[ BRUMM GOVERNANCE GATE ]
  +-- 1. Challenge Premise      -> "Why is this needed? Is the premise factually true?"
  +-- 2. Compute Blast Radius   -> Volume, environment, reversibility, dependency tree.
  +-- 3. Safe Transformation    -> DELETE -> SNAPSHOT -> DRY-RUN -> QUARANTINE.
  +-- 4. Dynamic Capability     -> Issue ephemeral, 60-second, audience-bound JEV lease.
      |
      +---> DENY with rationale & guidance (if premise is flawed)
      +---> CONSTRAIN & EXECUTE (if safe transformation exists)
      +---> ESCALATE (if critical & irreversible)
```

---

## 🤖 Use Brumm as a Claude Code Skill

Brumm ships as a Claude Code plugin. Once installed, Claude checks destructive actions (`rm -rf`, `DROP TABLE`, `terraform destroy`, `kubectl delete`, prod deploys) with Brumm before it runs them. Requires Node.js 22.5+ (`brew install node` on macOS).

Inside Claude Code:

```text
/plugin install brumm --marketplace agunggnn/brumm
```

On older Claude Code versions, use two steps:

```text
/plugin marketplace add agunggnn/brumm
/plugin install brumm@brumm
```

Try it: *"Use brumm to check: delete /data/db in production."* To use your own rules, put a `brumm-policy.yaml` in your project folder or set `BRUMM_POLICY_PATH`.

---

## 🚀 Quickstart

### 1. Run Policy Simulation CLI
Test whether an agent action is permitted, constrained, or denied:

```bash
# Test cleanup agent attempting to delete 700GB in production
node bin/brumm.mjs policy test \
  --policy ./brumm-policy.yaml \
  --agent cleanup-agent \
  --action delete \
  --resource backup-prod/cluster-archive \
  --size 700GB \
  --env production
```

Output:
```text
Decision: ESCALATE
Rule:     cleanup-agent-policy
Policy:   production-safeguards (hash: 8909abff)

Reasons:
- Requested size (751619276800 bytes) exceeds autonomous approval threshold (53687091200 bytes)
```

### 2. Programmatic API (`createGuard`)

```javascript
import { createGuard } from '@agunggnn/brumm';

// Strict context boundary by default: callers cannot spoof environment or agentId
const guard = createGuard({
  policy: './brumm-policy.yaml',
  agent: 'cleanup-agent',
  environment: 'production',
  // trustBoundary: 'strict', // 'strict' (default) blocks untrusted identity escalation; 'gateway' allows dynamic broker overrides
});

// Evaluate before invoking any tool call
const decision = guard.evaluate({
  action: 'delete',
  resource: 'backup-prod/old-logs',
  size: '10GB',
  count: 1, // Strict non-negative integer; fail-closed if rule enforces object limits
  hasSnapshot: true, // Strict boolean (string "false" or numbers 0/1 are rejected)
});

if (decision.allowed) {
  // Proceed with execution
} else if (decision.requiresApproval) {
  // Escalate to human supervisor
} else if (decision.isConstrained) {
  // Enforce required transformation (e.g. create snapshot first)
}
```

### 3. Execution Boundary & Tool Guard (`createExecutionGuard`)
Enforce capability verification directly at the physical tool execution boundary:

```javascript
import { createGuard, createExecutionGuard } from '@agunggnn/brumm';

const guard = createGuard({ policy: './brumm-policy.yaml' });
const executionGuard = createExecutionGuard({ guard });

// Protect an underlying sensitive tool (Cloud SDK, DB, OS process)
const protectedDelete = executionGuard.protect('delete', async (params, { capability }) => {
  // Guaranteed: capability is cryptographically signed, unexpired, and nonce is consumed
  return await executeRawDelete(params);
});

// Or run through the unified governance-to-execution pipeline:
const execution = await executionGuard.execute(
  {
    action: 'delete',
    resource: 'backup-prod/temp.log',
    parameters: { path: 'backup-prod/temp.log' },
    snapshot: true,
  },
  { agentId: 'cleanup-agent', environment: 'production' },
  async (params) => await executeRawDelete(params)
);

if (!execution.executed) {
  console.error('Execution blocked by Brumm:', execution.decision.reasons);
}
```

### 4. Dynamic Capability Verification & Trust Boundaries (Milestone P2.3)

Brumm enforces strict, fail-closed cryptographic and audience verification before granting execution:

- **Audience & User Subject Binding**: Capabilities are cryptographically bound to `agentId`, `taskUid`, and `user`. Calling tools with a mismatched user identity yields `USER_MISMATCH`. In `strict` trust boundary mode, callers cannot override or escalate user identity.
- **Fail-Closed Structural Validation**: Validates capability version (`1.0`), issuer (`brumm-governance-engine`), ID format (`cap_*`), nonce entropy, policy hash, subject schema, action, resource, constraints, and timestamps before signature processing.
- **Strict Expiration & Purge Semantics**: Leases expire strictly at `now >= expiresAt`. Replay tracking automatically purges nonces once expired.
- **Multi-Parameter Substitution Defense**: Execution guards inspect all candidate resource parameters (`resource`, `target`, `path`, `destination`, `dest`, `file`, `filePath`, `filepath`, `uri`, `url`, `source`, `src`, and S3 `bucket`+`key`), blocking any attempt to execute against resources differing from authorized capability bounds.
- **Process-Local Replay Architecture Notice**: `NonceTracker` protects against concurrent and sequential replays within the process. For distributed multi-replica or serverless clusters, back with a distributed CAS store (Redis `SET NX PX` or DynamoDB conditional put).

### 5. Run Test Suite
Brumm uses the zero-dependency Node 22+ native test runner:

```bash
npm test
npm run check
```

---

## 📑 Specification & Documentation Index

Brumm is specified across 15 modular architecture blueprints located in [`docs/`](docs/):

| Document | Purpose |
|---|---|
| 🛡️ **[`docs/AGENTIC-SAFETY.md`](docs/AGENTIC-SAFETY.md)** | The Honest Mistake Problem, Blast Radius factors, and safe transformation pipelines. |
| 🏛️ **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** | Target control plane: Agent Identity, JEV Engine, Memory Guard, Tool Guard, Risk Engine. |
| 🔑 **[`docs/CAPABILITY-MODEL.md`](docs/CAPABILITY-MODEL.md)** | Contextual, bounded dynamic capabilities vs broad static bearer credentials. |
| 📐 **[`docs/DESIGN-PRINCIPLES.md`](docs/DESIGN-PRINCIPLES.md)** | 10 foundational design principles: Least authority, bounded blast radius, fail-closed. |
| 🧪 **[`docs/EXAMPLES.md`](docs/EXAMPLES.md)** | Concrete walkthroughs: DB migrations, PII customer support, cleanup, release gates. |
| ⚡ **[`docs/JEV.md`](docs/JEV.md)** | The JEV execution model: Intent + Context + Policy + Risk $\to$ Dynamic Capability. |
| 🔌 **[`docs/MCP-SECURITY.md`](docs/MCP-SECURITY.md)** | Tool boundary enforcement: MCP request argument inspection and response sanitization. |
| 🧠 **[`docs/MEMORY-SECURITY.md`](docs/MEMORY-SECURITY.md)** | RAG & Vector Memory Guard: Controlled disclosure, memory classification, egress DLP. |
| ❓ **[`docs/OPEN-QUESTIONS.md`](docs/OPEN-QUESTIONS.md)** | 15 open engineering and cryptographic challenges (attestation, capability tokens). |
| ⚖️ **[`docs/POLICY-ENGINE.md`](docs/POLICY-ENGINE.md)** | Deterministic evaluation precedence over LLM self-policing; `brumm policy test` CLI. |
| 🗺️ **[`docs/ROADMAP.md`](docs/ROADMAP.md)** | 7-phase evolution: Foundation $\to$ Secrets $\to$ MCP $\to$ Memory $\to$ Execution $\to$ JEV $\to$ Platform. |
| 🔐 **[`docs/SECRET-SECURITY.md`](docs/SECRET-SECURITY.md)** | Brokered capabilities, canary credentials, anti-reflection, and memory dump resistance. |
| ☣️ **[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)** | Scoped threat analysis: Honest mistakes, indirect prompt injection, confused deputies. |
| 🔭 **[`docs/VISION.md`](docs/VISION.md)** | The core manifesto: From credential protection to autonomous agent safety. |
| 📖 **[`docs/README-DOCS.md`](docs/README-DOCS.md)** | Documentation reading guide and cross-references. |

---

## 🤝 Ecosystem Lineage

Brumm operates alongside the Hetzer armor ecosystem:

1. **[Hetzer](https://github.com/agunggnn/hetzer)** 🛡️: Single-command runtime armor, AES-256-GCM Grimoire vault, stream redactor, pre-commit hook, loopback HTTP credential broker.
2. **[Jagdpanzer](https://github.com/agunggnn/jagdpanzer)** 🚜: Multi-container stack orchestration, persistent vector/graph cognitive memory (Cognee), fleet ops.
3. **[Brumm](https://github.com/agunggnn/brumm)** 🐻: Agentic governance, Socratic refusal engine, blast radius containment, and JEV capability arbiter.

---

## 📄 License

Distributed under the **Apache-2.0** License.
