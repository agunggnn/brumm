/**
 * @file test/capability-verification-hardening.test.mjs
 * Security regression tests for Milestone P2.3:
 * Capability Verification, Structural Validation, Time Invariants,
 * Audience & User Subject Binding, and Execution Boundary Parameter Substitution Defense.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createExecutionGuard } from '../src/adapters/tool-adapter.mjs';
import {
  NonceTracker,
  globalNonceTracker,
  issueCapability,
  resolveSigningKey,
  verifyCapability,
} from '../src/core/capability.mjs';
import { createGuard } from '../src/index.mjs';
import { DecisionOutcome } from '../src/core/decision.mjs';
import { CapabilitySecurityError, ExecutionSecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const POLICY = compilePolicy({
  name: 'verification-hardening-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'alice-ops-rule',
      effect: 'ALLOW',
      agent: 'ops-agent',
      action: 'deploy',
      resource: 'prod/services/**',
      constraints: {
        absolute_max_size: '50MB',
        max_objects: 10,
      },
    },
    {
      id: 'cleanup-rule',
      effect: 'ALLOW',
      agent: 'cleanup-agent',
      action: 'delete',
      resource: 'backup-prod/**',
    },
  ],
});

const SIGNING_KEY = 'test-signing-key-32-chars-minimum-safe!';

describe('Milestone P2.3: Capability Subject Binding & User Audience Verification', () => {
  const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
  const context = { agentId: 'ops-agent', user: 'alice', taskUid: 'task_turn_101' };
  const decision = evaluatePolicy(POLICY, request, context);

  it('validates successfully when user matches the bound audience', () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    const verification = verifyCapability(
      capability,
      POLICY,
      request,
      { agentId: 'ops-agent', user: 'alice', taskUid: 'task_turn_101' },
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verification.valid, true);
  });

  it('rejects verification when caller presents a different user (USER_MISMATCH)', () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    // Attacker bob tries to present alice's capability
    const verification = verifyCapability(
      capability,
      POLICY,
      request,
      { agentId: 'ops-agent', user: 'bob', taskUid: 'task_turn_101' },
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'USER_MISMATCH');
    assert.match(verification.error, /Capability bound to user "alice", but invoked by "bob"/);
  });

  it('rejects verification when current context user is omitted (defaults to system)', () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    // Context without user defaults to 'system', which does not match 'alice'
    const verification = verifyCapability(
      capability,
      POLICY,
      request,
      { agentId: 'ops-agent', taskUid: 'task_turn_101' },
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'USER_MISMATCH');
    assert.match(verification.error, /Capability bound to user "alice", but invoked by "system"/);
  });

  it('detects tampering when capability subject user is modified in memory', () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    // Attacker tampers with user in capability lease to match their identity
    const tampered = {
      ...capability,
      subject: {
        ...capability.subject,
        user: 'attacker',
      },
    };

    const verification = verifyCapability(
      tampered,
      POLICY,
      request,
      { agentId: 'ops-agent', user: 'attacker', taskUid: 'task_turn_101' },
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'FORGERY_DETECTED');
    assert.match(verification.error, /Invalid capability signature: payload has been tampered with or forged/);
  });
});

describe('Milestone P2.3: Fail-Closed Verification on Malformed Context', () => {
  const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
  const context = { agentId: 'ops-agent', user: 'alice' };
  const decision = evaluatePolicy(POLICY, request, context);
  const capability = issueCapability({
    decision,
    request,
    context,
    options: { signingKey: SIGNING_KEY },
  });

  it('returns MALFORMED_CONTEXT without throwing when rawContext is null', () => {
    const verification = verifyCapability(capability, POLICY, request, null, { signingKey: SIGNING_KEY });
    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'MALFORMED_CONTEXT');
    assert.match(verification.error, /Agent context must be a non-null object or string/);
  });

  it('returns MALFORMED_CONTEXT without throwing when rawContext is a primitive number', () => {
    const verification = verifyCapability(capability, POLICY, request, 12345, { signingKey: SIGNING_KEY });
    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'MALFORMED_CONTEXT');
  });

  it('returns MALFORMED_CONTEXT without throwing when rawContext is a boolean', () => {
    const verification = verifyCapability(capability, POLICY, request, false, { signingKey: SIGNING_KEY });
    assert.equal(verification.valid, false);
    assert.equal(verification.code, 'MALFORMED_CONTEXT');
  });

  it('still throws CapabilitySecurityError on missing production signing key (distinguishing server config error)', () => {
    assert.throws(
      () => {
        resolveSigningKey(null, true);
      },
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'MISSING_SIGNING_KEY');
        return true;
      }
    );
  });
});

describe('Milestone P2.3: Strict Expiration Semantics & Purge Boundary', () => {
  const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
  const context = { agentId: 'ops-agent', user: 'alice' };
  const decision = evaluatePolicy(POLICY, request, context);

  it('rejects capability at the EXACT expiration timestamp (now === expiresAt)', () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    // Mock Date.now to return exact expiresAt
    const originalNow = Date.now;
    try {
      Date.now = () => capability.expiresAt;

      const verification = verifyCapability(capability, POLICY, request, context, {
        signingKey: SIGNING_KEY,
      });

      assert.equal(verification.valid, false);
      assert.equal(verification.code, 'CAPABILITY_EXPIRED');
    } finally {
      Date.now = originalNow;
    }
  });

  it('permits capability 1ms before expiration timestamp (now < expiresAt)', () => {
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    const originalNow = Date.now;
    try {
      Date.now = () => capability.expiresAt - 1;

      const verification = verifyCapability(capability, POLICY, request, context, {
        signingKey: SIGNING_KEY,
      });

      assert.equal(verification.valid, true);
    } finally {
      Date.now = originalNow;
    }
  });

  it('NonceTracker purges nonces whose lease has expired (now >= expiresAt)', () => {
    const tracker = new NonceTracker();
    const nonce = 'test-nonce-1234567890';
    const expiresAt = 1000000;

    tracker.consumed.set(nonce, expiresAt);

    const originalNow = Date.now;
    try {
      // 1ms before expiration: nonce is still tracked
      Date.now = () => expiresAt - 1;
      assert.equal(tracker.has(nonce), true);

      // Exactly at expiration: nonce is purged
      Date.now = () => expiresAt;
      assert.equal(tracker.has(nonce), false);
    } finally {
      Date.now = originalNow;
    }
  });
});

describe('Milestone P2.3: Capability Structural Validation & Invariants', () => {
  const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
  const context = { agentId: 'ops-agent', user: 'alice' };
  const decision = evaluatePolicy(POLICY, request, context);
  const validCapability = issueCapability({
    decision,
    request,
    context,
    options: { signingKey: SIGNING_KEY },
  });

  it('rejects null or non-object capability (INVALID_CAPABILITY)', () => {
    const res1 = verifyCapability(null, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res1.valid, false);
    assert.equal(res1.code, 'INVALID_CAPABILITY');

    const res2 = verifyCapability([1, 2, 3], POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res2.valid, false);
    assert.equal(res2.code, 'INVALID_CAPABILITY');
  });

  it('rejects unsupported capability version (INVALID_VERSION)', () => {
    const cap = { ...validCapability, version: '2.0' };
    const res = verifyCapability(cap, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res.valid, false);
    assert.equal(res.code, 'INVALID_VERSION');
  });

  it('rejects invalid capability issuer (INVALID_ISSUER)', () => {
    const cap = { ...validCapability, issuer: 'rogue-issuer' };
    const res = verifyCapability(cap, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res.valid, false);
    assert.equal(res.code, 'INVALID_ISSUER');
  });

  it('rejects malformed capability ID not starting with cap_ (MALFORMED_CAPABILITY)', () => {
    const cap = { ...validCapability, id: 'token_123456789' };
    const res = verifyCapability(cap, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res.valid, false);
    assert.equal(res.code, 'MALFORMED_CAPABILITY');
  });

  it('rejects malformed nonce (MALFORMED_NONCE)', () => {
    const cap1 = { ...validCapability, nonce: 'short' };
    const res1 = verifyCapability(cap1, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res1.valid, false);
    assert.equal(res1.code, 'MALFORMED_NONCE');

    const cap2 = { ...validCapability, nonce: 'not-a-hex-string-too-many-nonhex-chars!' };
    const res2 = verifyCapability(cap2, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res2.valid, false);
    assert.equal(res2.code, 'MALFORMED_NONCE');
  });

  it('rejects malformed policyHash (MALFORMED_POLICY_HASH)', () => {
    const cap = { ...validCapability, policyHash: 'not-64-hex' };
    const res = verifyCapability(cap, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res.valid, false);
    assert.equal(res.code, 'MALFORMED_POLICY_HASH');
  });

  it('rejects malformed subject (MALFORMED_SUBJECT)', () => {
    const cap1 = { ...validCapability, subject: null };
    const res1 = verifyCapability(cap1, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res1.valid, false);
    assert.equal(res1.code, 'MALFORMED_SUBJECT');

    const cap2 = { ...validCapability, subject: { agentId: '', user: 'alice' } };
    const res2 = verifyCapability(cap2, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res2.valid, false);
    assert.equal(res2.code, 'MALFORMED_SUBJECT');

    const cap3 = { ...validCapability, subject: { agentId: 'ops-agent', user: '' } };
    const res3 = verifyCapability(cap3, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res3.valid, false);
    assert.equal(res3.code, 'MALFORMED_SUBJECT');

    const cap4 = { ...validCapability, subject: { agentId: 'ops-agent', user: 'alice', taskUid: 9999 } };
    const res4 = verifyCapability(cap4, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res4.valid, false);
    assert.equal(res4.code, 'MALFORMED_SUBJECT');
  });

  it('rejects malformed action or resource (MALFORMED_ACTION / MALFORMED_RESOURCE)', () => {
    const cap1 = { ...validCapability, action: '' };
    const res1 = verifyCapability(cap1, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res1.valid, false);
    assert.equal(res1.code, 'MALFORMED_ACTION');

    const cap2 = { ...validCapability, resource: '   ' };
    const res2 = verifyCapability(cap2, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res2.valid, false);
    assert.equal(res2.code, 'MALFORMED_RESOURCE');
  });

  it('rejects malformed constraints (MALFORMED_CONSTRAINTS)', () => {
    const cap = { ...validCapability, constraints: 'not-an-object' };
    const res = verifyCapability(cap, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res.valid, false);
    assert.equal(res.code, 'MALFORMED_CONSTRAINTS');
  });

  it('rejects malformed timestamps (MALFORMED_TIMESTAMPS)', () => {
    const cap1 = { ...validCapability, issuedAt: 'invalid' };
    const res1 = verifyCapability(cap1, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res1.valid, false);
    assert.equal(res1.code, 'MALFORMED_TIMESTAMPS');

    const cap2 = { ...validCapability, expiresAt: -100 };
    const res2 = verifyCapability(cap2, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res2.valid, false);
    assert.equal(res2.code, 'MALFORMED_TIMESTAMPS');
  });

  it('rejects inverted or non-positive time invariants (INVALID_TIME_INVARIANT)', () => {
    // expiresAt <= issuedAt
    const now = Date.now();
    const cap1 = { ...validCapability, issuedAt: now, expiresAt: now };
    const res1 = verifyCapability(cap1, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res1.valid, false);
    assert.equal(res1.code, 'INVALID_TIME_INVARIANT');

    const cap2 = { ...validCapability, issuedAt: now + 5000, expiresAt: now };
    const res2 = verifyCapability(cap2, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res2.valid, false);
    assert.equal(res2.code, 'INVALID_TIME_INVARIANT');
  });

  it('rejects capability TTL outside 1s - 300s window (INVALID_TIME_INVARIANT)', () => {
    const now = Date.now();

    // TTL 500ms (< 1000ms)
    const capShort = { ...validCapability, issuedAt: now, expiresAt: now + 500 };
    const resShort = verifyCapability(capShort, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(resShort.valid, false);
    assert.equal(resShort.code, 'INVALID_TIME_INVARIANT');

    // TTL 600s (> 300s)
    const capLong = { ...validCapability, issuedAt: now, expiresAt: now + 600000 };
    const resLong = verifyCapability(capLong, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(resLong.valid, false);
    assert.equal(resLong.code, 'INVALID_TIME_INVARIANT');
  });

  it('rejects invalid or non-64-hex signatures (FORGERY_DETECTED)', () => {
    const cap = { ...validCapability, signature: 'short-signature' };
    const res = verifyCapability(cap, POLICY, request, context, { signingKey: SIGNING_KEY });
    assert.equal(res.valid, false);
    assert.equal(res.code, 'FORGERY_DETECTED');
  });
});

describe('Milestone P2.3: Execution Boundary Identity & Multi-Parameter Substitution Defense', () => {
  const guard = {
    policy: POLICY,
    evaluate: (req, ctx) => evaluatePolicy(POLICY, req, ctx),
  };
  const executionGuard = createExecutionGuard({ guard, signingKey: SIGNING_KEY });

  it('executes successfully when caller omits context by falling back to capability subject user', async () => {
    const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
    const context = { agentId: 'ops-agent', user: 'alice', taskUid: 'task_turn_101' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    let executedWithParams = null;
    const protectedDeploy = executionGuard.protect('deploy', async (params) => {
      executedWithParams = params;
      return { status: 'DEPLOYED' };
    });

    // Caller does NOT pass context override; effectiveContext must preserve capability.subject.user
    const res = await protectedDeploy(
      { resource: 'prod/services/web' },
      { capability, request }
    );

    assert.equal(res.status, 'DEPLOYED');
    assert.equal(executedWithParams._authorizedResource, 'prod/services/web');
    assert.equal(executedWithParams._authorizedAction, 'deploy');
  });

  it('blocks execution when caller attempts user identity substitution at execution boundary', async () => {
    const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
    const context = { agentId: 'ops-agent', user: 'alice' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    const protectedDeploy = executionGuard.protect('deploy', async () => ({ status: 'DEPLOYED' }));

    // Caller passes eve as user context at execution boundary
    await assert.rejects(
      async () => {
        await protectedDeploy(
          { resource: 'prod/services/web' },
          { capability, request, context: { agentId: 'ops-agent', user: 'eve' } }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'USER_MISMATCH');
        assert.match(err.message, /Capability bound to user "alice", but invoked by "eve"/);
        return true;
      }
    );
  });

  it('blocks parameter substitution across multiple candidate keys (destination, file, path, etc.)', async () => {
    const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
    const context = { agentId: 'ops-agent', user: 'alice' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    const protectedDeploy = executionGuard.protect('deploy', async () => ({ status: 'DEPLOYED' }));

    // Attacker passes legitimate resource: 'prod/services/web', but malicious destination: '/etc/shadow'
    await assert.rejects(
      async () => {
        await protectedDeploy(
          {
            resource: 'prod/services/web',
            destination: '/etc/shadow',
          },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "destination"/);
        return true;
      }
    );

    // Attacker passes malicious file in filePath parameter
    await assert.rejects(
      async () => {
        await protectedDeploy(
          {
            filePath: '/var/secret/keys.json',
          },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "filePath"/);
        return true;
      }
    );
  });

  it('blocks parameter substitution targeting unauthorized composite S3 bucket and key', async () => {
    const request = { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 };
    const context = { agentId: 'ops-agent', user: 'alice' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({
      decision,
      request,
      context,
      options: { signingKey: SIGNING_KEY },
    });

    const protectedDeploy = executionGuard.protect('deploy', async () => ({ status: 'DEPLOYED' }));

    await assert.rejects(
      async () => {
        await protectedDeploy(
          {
            bucket: 'unauthorized-bucket',
            key: 'database.dump',
          },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "bucket\/key"/);
        return true;
      }
    );
  });
});

describe('Milestone P2.3: Context Trust Boundary User Override in Guard', () => {
  const strictGuard = createGuard({
    policy: POLICY,
    agent: 'ops-agent',
    environment: 'production',
    user: 'alice',
    trustBoundary: 'strict',
  });

  const gatewayGuard = createGuard({
    policy: POLICY,
    trustBoundary: 'gateway',
  });

  it('blocks untrusted caller from overriding bound user in strict mode', () => {
    const decision = strictGuard.evaluate(
      { action: 'deploy', resource: 'prod/services/web' },
      { user: 'eve' }
    );

    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Security context violation/);
    assert.match(decision.reasons[0], /Untrusted caller attempted to override bound user "alice" with "eve"/);
  });

  it('permits dynamic user dispatch in gateway mode', () => {
    const decision = gatewayGuard.evaluate(
      { action: 'deploy', resource: 'prod/services/web', size: '5MB', count: 1 },
      { agentId: 'ops-agent', user: 'alice', environment: 'production' }
    );

    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });
});
