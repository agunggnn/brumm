/**
 * @file test/capability-and-execution.test.mjs
 * Comprehensive unit tests for Milestone P2:
 * Dynamic Capability Issuance, Cryptographic Verification, Single-Use Nonce Replay Defense,
 * TOCTOU Policy Hash Binding, and Execution Boundary Enforcement.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createExecutionGuard } from '../src/adapters/tool-adapter.mjs';
import {
  consumeCapability,
  issueCapability,
  verifyCapability,
} from '../src/core/capability.mjs';
import { DecisionOutcome } from '../src/core/decision.mjs';
import { CapabilitySecurityError, ExecutionSecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const TEST_POLICY_V1 = compilePolicy({
  name: 'test-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'cleanup-rule',
      effect: 'ALLOW',
      agent: 'cleanup-agent',
      action: 'delete',
      resource: 'backup-prod/**',
      constraints: {
        absolute_max_size: '100GB',
        max_objects: 500,
        require_snapshot: true,
      },
    },
    {
      id: 'critical-wipe-deny',
      effect: 'DENY',
      action: 'delete',
      resource: '/data/*',
    },
  ],
});

const TEST_POLICY_V2 = compilePolicy({
  name: 'test-policy',
  version: '2.0',
  defaultEffect: 'DENY',
  rules: [
    // In V2, the cleanup rule was removed by an admin!
    {
      id: 'critical-wipe-deny',
      effect: 'DENY',
      action: 'delete',
      resource: '**',
    },
  ],
});

describe('Milestone P2: Dynamic Capability Issuance', () => {
  it('issues a cryptographically signed capability for an ALLOW decision', () => {
    const request = {
      action: 'delete',
      resource: 'backup-prod/old-logs',
      size: '20GB',
      count: 50,
      hasSnapshot: true,
    };
    const context = {
      agentId: 'cleanup-agent',
      taskUid: 'task_turn_123',
    };

    const decision = evaluatePolicy(TEST_POLICY_V1, request, context);
    assert.equal(decision.outcome, DecisionOutcome.ALLOW);

    const capability = issueCapability({
      decision,
      request,
      context,
      options: { ttlSeconds: 60, signingKey: 'test-secret-key-123' },
    });

    assert.ok(capability.id.startsWith('cap_'));
    assert.equal(capability.version, '1.0');
    assert.ok(capability.nonce);
    assert.equal(capability.policyHash, decision.policyHash);
    assert.equal(capability.action, 'delete');
    assert.equal(capability.resource, 'backup-prod/old-logs');
    assert.equal(capability.subject.agentId, 'cleanup-agent');
    assert.equal(capability.subject.taskUid, 'task_turn_123');
    assert.equal(capability.constraints.maxBytes, 100 * 1000 * 1000 * 1000);
    assert.equal(capability.constraints.maxObjects, 500);
    assert.ok(capability.signature);
    assert.equal(capability.signature.length, 64);
  });

  it('refuses to issue capability for a DENY decision', () => {
    const request = {
      action: 'delete',
      resource: '/data/prod-db',
    };
    const context = { agentId: 'cleanup-agent' };

    const decision = evaluatePolicy(TEST_POLICY_V1, request, context);
    assert.equal(decision.outcome, DecisionOutcome.DENY);

    assert.throws(
      () => {
        issueCapability({
          decision,
          request,
          context,
        });
      },
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'UNPERMITTED_DECISION');
        return true;
      }
    );
  });
});

describe('Milestone P2: Cryptographic Signature & Tampering Defense', () => {
  const request = {
    action: 'delete',
    resource: 'backup-prod/old-logs',
    size: '10GB',
    count: 1,
    hasSnapshot: true,
  };
  const context = { agentId: 'cleanup-agent' };
  const signingKey = 'my-secret-signing-key';

  const decision = evaluatePolicy(TEST_POLICY_V1, request, context);
  const validCapability = issueCapability({
    decision,
    request,
    context,
    options: { signingKey },
  });

  it('verifies a genuine capability successfully', () => {
    const verification = verifyCapability(
      validCapability,
      TEST_POLICY_V1,
      request,
      context,
      { signingKey }
    );
    assert.equal(verification.valid, true);
  });

  it('detects tampering when an attacker expands the capability constraints', () => {
    // Attacker modifies the signed capability in memory
    const tampered = {
      ...validCapability,
      constraints: {
        ...validCapability.constraints,
        maxBytes: 9999999999999, // Artificially inflated
      },
    };

    const verification = verifyCapability(
      tampered,
      TEST_POLICY_V1,
      request,
      context,
      { signingKey }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'FORGERY_DETECTED');
    assert.match(verification.error, /tampered with or forged/);
  });

  it('detects tampering when an attacker changes the action in capability', () => {
    const tampered = {
      ...validCapability,
      action: 'admin:purge_all',
    };

    const verification = verifyCapability(
      tampered,
      TEST_POLICY_V1,
      request,
      context,
      { signingKey }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'FORGERY_DETECTED');
  });
});

describe('Milestone P2: Single-Use Nonce Replay Defense', () => {
  it('blocks replay attacks when the same capability is presented twice', () => {
    const request = {
      action: 'delete',
      resource: 'backup-prod/data-chunk',
      size: '10GB',
      count: 1,
      hasSnapshot: true,
    };
    const context = { agentId: 'cleanup-agent' };

    const decision = evaluatePolicy(TEST_POLICY_V1, request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
    });

    // 1st invocation: verifies and consumes nonce
    const verification1 = verifyCapability(capability, TEST_POLICY_V1, request, context);
    assert.equal(verification1.valid, true);
    consumeCapability(capability);

    // 2nd invocation (replay attack): must be REJECTED!
    const verification2 = verifyCapability(capability, TEST_POLICY_V1, request, context);
    assert.equal(verification2.valid, false);
    assert.equal(verification2.code, 'REPLAY_ATTACK_DETECTED');
    assert.match(verification2.error, /already been consumed/);
  });
});

describe('Milestone P2: TOCTOU Stale Policy Revocation', () => {
  it('revokes capability if the underlying policy is modified after issuance', () => {
    const request = {
      action: 'delete',
      resource: 'backup-prod/data-chunk',
      size: '10GB',
      count: 1,
      hasSnapshot: true,
    };
    const context = { agentId: 'cleanup-agent' };

    // Issued under Policy V1
    const decision = evaluatePolicy(TEST_POLICY_V1, request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
    });

    // Admin updates policy to V2 (which denies cleanup)
    // Verification against V2 detects policy hash mismatch!
    const verification = verifyCapability(capability, TEST_POLICY_V2, request, context);
    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'STALE_POLICY_REVOKED');
    assert.match(verification.error, /Lease revoked due to policy modification/);
  });
});

describe('Milestone P2: Subject & Resource Binding', () => {
  const request = {
    action: 'delete',
    resource: 'backup-prod/data-chunk',
    size: '10GB',
    count: 1,
    hasSnapshot: true,
  };
  const context = { agentId: 'cleanup-agent', taskUid: 'task-1' };

  const decision = evaluatePolicy(TEST_POLICY_V1, request, context);
  const capability = issueCapability({ decision, request, context });

  it('rejects invocation by a different agent (confused deputy attack)', () => {
    const verification = verifyCapability(
      capability,
      TEST_POLICY_V1,
      request,
      { agentId: 'rogue-agent', taskUid: 'task-1' }
    );
    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'AUDIENCE_MISMATCH');
  });

  it('rejects invocation when target resource does not match capability', () => {
    const verification = verifyCapability(
      capability,
      TEST_POLICY_V1,
      { action: 'delete', resource: 'backup-prod/different-file', size: '10GB', count: 1, hasSnapshot: true },
      context
    );
    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'RESOURCE_MISMATCH');
  });
});

describe('Milestone P2: Execution Boundary & Tool Adapter Enforcement', () => {
  const fakeToolExecutionLog = [];

  // Underlying sensitive tool function (e.g. OS file delete or Cloud API)
  async function rawDeleteTool(params, securityContext) {
    fakeToolExecutionLog.push({ params, verified: securityContext.verified });
    return { status: 'DELETED', target: params.target };
  }

  const guard = {
    policy: TEST_POLICY_V1,
    evaluate: (req, ctx) => evaluatePolicy(TEST_POLICY_V1, req, ctx),
  };

  const executionGuard = createExecutionGuard({ guard });

  it('blocks direct invocation of tool when missing capability', async () => {
    const protectedTool = executionGuard.protect('delete', rawDeleteTool);

    await assert.rejects(
      async () => {
        // Direct tool invocation attempting to bypass governance
        await protectedTool({ target: '/data/prod' }, {});
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'MISSING_CAPABILITY');
        return true;
      }
    );
  });

  it('executes tool successfully when valid capability is presented through pipeline', async () => {
    const result = await executionGuard.execute(
      {
        action: 'delete',
        resource: 'backup-prod/temp.log',
        parameters: { target: 'backup-prod/temp.log' },
        size: '10GB',
        count: 1,
        snapshot: true,
      },
      { agentId: 'cleanup-agent' },
      rawDeleteTool
    );

    assert.equal(result.executed, true);
    assert.equal(result.result.status, 'DELETED');
    assert.ok(result.capability);
    assert.ok(result.decision.allowed);
  });

  it('blocks execution without invoking tool when policy evaluation DENIES the request', async () => {
    const initialLogLength = fakeToolExecutionLog.length;

    const result = await executionGuard.execute(
      {
        action: 'delete',
        resource: '/data/prod-db', // Prohibited critical root!
        parameters: { target: '/data/prod-db' },
      },
      { agentId: 'cleanup-agent' },
      rawDeleteTool
    );

    assert.equal(result.executed, false);
    assert.equal(result.decision.outcome, DecisionOutcome.DENY);
    // Tool was NEVER invoked!
    assert.equal(fakeToolExecutionLog.length, initialLogLength);
  });

  it('blocks re-execution when an attacker attempts to reuse the capability', async () => {
    const protectedTool = executionGuard.protect('delete', rawDeleteTool);

    const request = {
      action: 'delete',
      resource: 'backup-prod/item',
      size: '10GB',
      count: 1,
      hasSnapshot: true,
    };
    const context = { agentId: 'cleanup-agent' };

    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context });

    // 1st call: succeeds
    await protectedTool({ target: 'backup-prod/item' }, { capability, request, context });

    // 2nd call (replay): blocked!
    await assert.rejects(
      async () => {
        await protectedTool({ target: 'backup-prod/item' }, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'REPLAY_ATTACK_DETECTED');
        return true;
      }
    );
  });
});
