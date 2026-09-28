# Design Principles

## 1. Agent Security Is Not the Same as Agent Alignment

An agent can be aligned with its interpreted objective and still produce an unsafe outcome.

Security must therefore exist outside the model.

## 2. Authorization Is Not Safety

Being allowed to perform an action does not mean the action is safe in every context.

## 3. Least Authority

Grant the minimum authority necessary.

## 4. Minimum Disclosure

Provide the minimum information necessary.

## 5. Bound the Blast Radius

Every powerful operation should have explicit limits.

## 6. Prefer Reversible Operations

Snapshots, quarantine, dry-run, and staged execution should be preferred when practical.

## 7. Deterministic Enforcement

LLMs can assist with interpretation, but critical security decisions should rely on deterministic enforcement wherever practical.

## 8. Fail Closed for Critical Operations

If authorization cannot be established for a critical destructive action, deny or require approval.

## 9. Do Not Confuse Encryption With Access Control

Encryption at rest does not prevent an authorized model from seeing decrypted information.

## 10. Do Not Confuse Credentials With Capabilities

A credential may provide broad access.

A capability can represent bounded authority.

## 11. Integrate With Existing Security

Hetzer should work with:

- Vault
- 1Password
- cloud secret managers
- cloud IAM
- Kubernetes RBAC
- existing identity systems
- vector databases
- MCP

## 12. Honest Security Claims

Never use terms such as:

- zero plaintext
- zero trust
- impossible to leak
- unhackable
- guaranteed safe

without clearly defining the boundary and evidence.

## 13. Observable Decisions

Every important policy decision should be explainable without exposing secrets.

## 14. Human Control

Humans should remain able to revoke, constrain, and override agentic authority.

## 15. Autonomy Should Be Earned

Autonomy should increase with demonstrated safety and decrease when risk increases.
