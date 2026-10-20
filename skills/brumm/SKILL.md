---
name: brumm
description: Policy gate for destructive or irreversible actions. Use BEFORE running anything that deletes, wipes, drops, destroys, restarts, or deploys — e.g. rm -rf, DROP TABLE, terraform destroy, kubectl delete, aws s3 rm, docker system prune, deploys to production — and whenever the user says "check with brumm", "is this safe", or "blast radius". Evaluates the action with the Brumm CLI and follows its ALLOW / CONSTRAIN / ESCALATE / DENY decision.
---

# Brumm — the Denial Smart Boss

Brumm is a deterministic policy engine. Ask it before you act, then obey the answer.
Never treat your own reasoning as approval for a destructive action.

## 1. Find the CLI

The CLI lives two folders above this skill's base directory: `<skill-base-dir>/../../bin/brumm.mjs`.
Call it `BRUMM` below. It needs Node.js 22.5 or newer (`node --version`).
If that file does not exist, use `npx -y github:agunggnn/brumm` as `BRUMM`.

## 2. Evaluate the action

```bash
node "$BRUMM" evaluate \
  --agent claude-code \
  --action <delete|write|deploy|restart|read|...> \
  --resource <path, bucket/key, table, or service> \
  --env <production|staging|development> \
  [--size 700GB] [--count 120] [--snapshot] [--dry-run] [--json]
```

- Fill in `--size` and `--count` when you can measure them first (`du -sh`, `find ... | wc -l`, `SELECT count(*)`). Rules with size/count limits fail closed when they are missing.
- Pass `--snapshot` only if a snapshot/backup really exists. Pass `--dry-run` only for a real dry run.
- Pick `--env` from the real target. If unsure, use `production`.

Policy lookup order: `--policy <file>`, then `$BRUMM_POLICY_PATH`, then `./brumm-policy.yaml` in the current directory, then the bundled default policy.

## 3. Obey the decision (exit code)

| Exit | Decision   | What you do |
|------|------------|-------------|
| 0    | ALLOW      | Proceed. Mention the matched rule in one line. |
| 3    | CONSTRAIN  | Do NOT run the original command. Run the suggested safe step first (snapshot → dry-run → quarantine), then evaluate again. |
| 2    | ESCALATE   | Stop. Show the user the reasons and blast radius, and ask for explicit approval. |
| 1    | DENY       | Stop. Show the reasons, challenge the premise ("why is this needed?"), and offer a safer alternative (move to quarantine, archive, smaller scope). |

Always show the user the `Decision`, `Rule`, and `Reasons` lines Brumm printed.
Do not edit the policy file to get a different answer unless the user explicitly asks you to.
