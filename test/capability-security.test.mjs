/**
 * @file test/capability-security.test.mjs
 * Security regression tests for Dynamic Capability (JEV Primitive):
 * Concurrent atomic replay defense, key management, TOCTOU revocation,
 * cross-boundary replays, tampering defense, and expiration boundaries.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  globalNonceTracker,
  issueCapability,
  resolveSigningKey,
  verifyCapability,
} from '../src/core/capability.mjs';
import { DecisionOutcome } from '../src/core/decision.mjs';
import { CapabilitySecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const POLICY_V1 = compilePolicy({
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
      },
    },
  ],
});

const POLICY_V2 = compilePolicy({
  name: 'test-policy',
  version: '2.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'deny-all',
      effect: 'DENY',
      action: '*',
      resource: '**',
    },
  ],
});

describe('Capability Security: Atomic Replay Defense & Concurrency', () => {
  const request = { action: 'delete', resource: 'backup-prod/test' };
  const context = { agentId: 'cleanup-agent', taskUid: 'task-1' };
  const signingKey = 'test-signing-key-minimum-32-chars-long';

  const decision = evaluatePolicy(POLICY_V1, request, context);

  it('atomically prevents concurrent reuse of the same capability lease', async () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey },
    });

    // Simulate 10 concurrent verification & consumption attempts
    const attempts = await Promise.all(
      Array.from({ length: 10 }, async () => {
        return verifyCapability(capability, POLICY_V1, request, context, {
          signingKey,
          consume: true, // Atomic verify and consume
        });
      })
    );

    const successful = attempts.filter(a => a.valid === true);
    const blockedReplays = attempts.filter(
      a => a.valid === false && a.code === 'REPLAY_ATTACK_DETECTED'
    );

    // Exactly ONE request must succeed; all others must be blocked!
    assert.equal(successful.length, 1);
    assert.equal(blockedReplays.length, 9);
  });
});

describe('Capability Security: Signing Key Management & Production Mode', () => {
  it('throws CapabilitySecurityError in production mode if signing key is missing', () => {
    assert.throws(
      () => {
        // Simulating production mode without key
        resolveSigningKey(null, true);
      },
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'MISSING_SIGNING_KEY');
        return true;
      }
    );
  });

  it('accepts explicit signing key in production mode (min 32 chars)', () => {
    const key = 'a-very-secure-32-character-secret-key-123';
    const resolved = resolveSigningKey(key, true);
    assert.equal(resolved, key);
  });
});

describe('Capability Security: TOCTOU Stale Policy Revocation', () => {
  const request = { action: 'delete', resource: 'backup-prod/test' };
  const context = { agentId: 'cleanup-agent' };
  const signingKey = 'test-signing-key-minimum-32-chars-long';

  it('revokes capability immediately when policy hash changes after issuance', () => {
    const decision = evaluatePolicy(POLICY_V1, request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey },
    });

    // Verifying against POLICY_V2 (which has a different hash) must fail
    const verification = verifyCapability(capability, POLICY_V2, request, context, {
      signingKey,
    });

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'STALE_POLICY_REVOKED');
    assert.match(verification.error, /Lease revoked due to policy modification/);
  });
});

describe('Capability Security: Cross-Boundary Replay Rejections', () => {
  const request = { action: 'delete', resource: 'backup-prod/data-1' };
  const context = { agentId: 'cleanup-agent', taskUid: 'task-1' };
  const signingKey = 'test-signing-key-minimum-32-chars-long';

  const decision = evaluatePolicy(POLICY_V1, request, context);
  const capability = issueCapability({
    decision,
    request,
    context,
    options: { signingKey },
  });

  it('rejects cross-agent replay (confused deputy attack)', () => {
    const verification = verifyCapability(
      capability,
      POLICY_V1,
      request,
      { agentId: 'attacker-agent', taskUid: 'task-1' },
      { signingKey }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'AUDIENCE_MISMATCH');
  });

  it('rejects cross-task replay (turn reuse attack)', () => {
    const verification = verifyCapability(
      capability,
      POLICY_V1,
      request,
      { agentId: 'cleanup-agent', taskUid: 'task-turn-attacker' },
      { signingKey }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'TASK_MISMATCH');
  });

  it('rejects cross-resource replay (resource substitution attack)', () => {
    const verification = verifyCapability(
      capability,
      POLICY_V1,
      { action: 'delete', resource: 'backup-prod/data-DIFFERENT' },
      context,
      { signingKey }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'RESOURCE_MISMATCH');
  });
});

describe('Capability Security: Expiration Boundary', () => {
  const request = { action: 'delete', resource: 'backup-prod/test' };
  const context = { agentId: 'cleanup-agent' };
  const signingKey = 'test-signing-key-minimum-32-chars-long';

  it('rejects expired capability leases', async () => {
    const decision = evaluatePolicy(POLICY_V1, request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { ttlSeconds: 1, signingKey }, // 1-second TTL
    });

    // Wait 1.1 seconds for lease to expire
    await new Promise(resolve => setTimeout(resolve, 1100));

    const verification = verifyCapability(capability, POLICY_V1, request, context, {
      signingKey,
    });

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'CAPABILITY_EXPIRED');
  });
});
