/**
 * @file test/tool-adapter.test.mjs
 * Security tests for Execution Boundary & Tool Guard Adapter:
 * Parameter substitution defense, CONSTRAIN pipeline enforcement,
 * direct invocation bypass blocking, and verified parameter injection.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createExecutionGuard } from '../src/adapters/tool-adapter.mjs';
import { issueCapability } from '../src/core/capability.mjs';
import { DecisionOutcome } from '../src/core/decision.mjs';
import { ExecutionSecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const POLICY = compilePolicy({
  name: 'adapter-test-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'cleanup-safe',
      effect: 'ALLOW',
      agent: 'cleanup-agent',
      action: 'delete',
      resource: 'backup-prod/allowed-zone/**',
    },
    {
      id: 'cleanup-constrained',
      effect: 'ALLOW',
      agent: 'cleanup-agent',
      action: 'delete',
      resource: 'backup-prod/snapshot-zone/**',
      constraints: {
        require_snapshot: true,
      },
    },
  ],
});

describe('Execution Boundary: Parameter & Resource Substitution Defense', () => {
  const executionLog = [];

  async function mockExecutor(params, secContext) {
    executionLog.push({ params, secContext });
    return { status: 'SUCCESS', target: params.target || params.resource };
  }

  const guard = {
    policy: POLICY,
    evaluate: (req, ctx) => evaluatePolicy(POLICY, req, ctx),
  };

  const signingKey = 'signing-key-with-at-least-32-chars-long';
  const executionGuard = createExecutionGuard({ guard, signingKey });

  it('detects and blocks parameter substitution where caller params target a different resource', async () => {
    const authorizedRequest = {
      action: 'delete',
      resource: 'backup-prod/allowed-zone/safe-file.txt',
    };
    const context = { agentId: 'cleanup-agent' };

    const decision = guard.evaluate(authorizedRequest, context);
    const capability = issueCapability({
      decision,
      request: authorizedRequest,
      context,
      options: { signingKey },
    });

    const protectedDelete = executionGuard.protect('delete', mockExecutor);

    // Attacker passes capability for safe-file.txt, but target in params points to sensitive-db.sql!
    await assert.rejects(
      async () => {
        await protectedDelete(
          { target: 'backup-prod/allowed-zone/sensitive-db.sql' },
          { capability, request: authorizedRequest, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /Parameter substitution attack detected/);
        return true;
      }
    );
  });

  it('injects verified immutable authorized metadata into executor parameters', async () => {
    const authorizedRequest = {
      action: 'delete',
      resource: 'backup-prod/allowed-zone/safe-file.txt',
    };
    const context = { agentId: 'cleanup-agent' };

    const decision = guard.evaluate(authorizedRequest, context);
    const capability = issueCapability({
      decision,
      request: authorizedRequest,
      context,
      options: { signingKey },
    });

    const protectedDelete = executionGuard.protect('delete', mockExecutor);

    const res = await protectedDelete(
      { target: 'backup-prod/allowed-zone/safe-file.txt', customFlag: true },
      { capability, request: authorizedRequest, context }
    );

    assert.equal(res.status, 'SUCCESS');
    const lastCall = executionLog[executionLog.length - 1];
    assert.equal(lastCall.params._authorizedResource, 'backup-prod/allowed-zone/safe-file.txt');
    assert.equal(lastCall.params._authorizedAction, 'delete');
    assert.ok(lastCall.secContext.verified);
  });
});

describe('Execution Boundary: CONSTRAIN Transformation Pipeline Enforcement', () => {
  async function mockExecutor(params) {
    return { status: 'DELETED', target: params.target };
  }

  const guard = {
    policy: POLICY,
    evaluate: (req, ctx) => evaluatePolicy(POLICY, req, ctx),
  };

  const signingKey = 'signing-key-with-at-least-32-chars-long';
  const executionGuard = createExecutionGuard({ guard, signingKey });

  it('blocks execution when action is CONSTRAIN and required snapshot is missing', async () => {
    const result = await executionGuard.execute(
      {
        action: 'delete',
        resource: 'backup-prod/snapshot-zone/db-backup',
        parameters: { target: 'backup-prod/snapshot-zone/db-backup' },
        snapshot: false, // Snapshot NOT taken!
      },
      { agentId: 'cleanup-agent' },
      mockExecutor
    );

    assert.equal(result.executed, false);
    assert.equal(result.constrained, true);
    assert.equal(result.decision.outcome, DecisionOutcome.CONSTRAIN);
    assert.match(result.error, /action requires transformation step \(SNAPSHOT\)/);
    assert.equal(result.suggestedTransform.step, 'SNAPSHOT');
  });

  it('allows execution when action is CONSTRAIN and required snapshot is provided', async () => {
    const result = await executionGuard.execute(
      {
        action: 'delete',
        resource: 'backup-prod/snapshot-zone/db-backup',
        parameters: { target: 'backup-prod/snapshot-zone/db-backup' },
        snapshot: true, // Snapshot fulfilled!
      },
      { agentId: 'cleanup-agent' },
      mockExecutor
    );

    assert.equal(result.executed, true);
    assert.equal(result.result.status, 'DELETED');
    assert.ok(result.capability);
  });
});
