/**
 * @file test/compiled-policy-trust-and-schema.test.mjs
 * Security regression tests for Milestone P2.3.3:
 * - Compiled-policy trust boundary hardening in createGuard()
 * - Branding & cryptographic integrity verification in isCompiledPolicy()
 * - Capability nonce, constraints, and TTL strictness
 * - Large number precision bounds in parseByteSize()
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  COMPILED_POLICY_BRAND,
  CapabilitySecurityError,
  DecisionOutcome,
  PolicyValidationError,
  compilePolicy,
  createGuard,
  isCompiledPolicy,
  issueCapability,
  parseByteSize,
  verifyCapability,
} from '../src/index.mjs';

const SIGNING_KEY = 'test-signing-key-for-p2-3-3-boundary-tests';

describe('Milestone P2.3.3: Compiled-Policy Trust Boundary in createGuard()', () => {
  it('rejects raw uncompiled policy object carrying a fake .hash string', () => {
    // Attacker supplies raw object with fake hash to bypass compilation & schema validation
    const fakePolicy = {
      hash: 'fake-hash-attempting-to-bypass-schema-validation-and-deep-freeze',
      name: 'fake-policy',
      rules: [
        {
          id: 'evil-rule',
          effect: 'ALLOW',
          agent: '*',
          action: '*',
          resource: '*',
        },
      ],
    };

    assert.throws(
      () => createGuard({ policy: fakePolicy }),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /Unknown top-level field in policy: "hash"/);
        return true;
      }
    );
  });

  it('accepts authentic compiled policy from compilePolicy()', () => {
    const raw = {
      name: 'authentic-policy',
      version: '1.0',
      defaultEffect: 'DENY',
      rules: [
        {
          id: 'read-rule',
          effect: 'ALLOW',
          agent: 'reader-agent',
          action: 'read',
          resource: 'public/**',
        },
      ],
    };

    const compiled = compilePolicy(raw);
    assert.equal(isCompiledPolicy(compiled), true);

    const guard = createGuard({ policy: compiled, agent: 'reader-agent' });
    assert.equal(guard.policy, compiled);
    assert.equal(guard.policyHash, compiled.hash);

    const decision = guard.evaluate(
      { action: 'read', resource: 'public/doc.txt' },
      { agentId: 'reader-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });

  it('compiles and deep-freezes raw policy objects, resisting post-creation mutation', () => {
    const raw = {
      name: 'mutable-source-policy',
      version: '1.0',
      defaultEffect: 'DENY',
      rules: [
        {
          id: 'safe-rule',
          effect: 'ALLOW',
          agent: 'agent-1',
          action: 'read',
          resource: 'data/**',
        },
      ],
    };

    const guard = createGuard({ policy: raw });

    // Guard policy must be frozen
    assert.equal(Object.isFrozen(guard.policy), true);
    assert.equal(Object.isFrozen(guard.policy.rules), true);

    // Attempting to mutate caller raw object must NOT affect guard's compiled policy
    raw.rules.push({
      id: 'injected-rule',
      effect: 'ALLOW',
      agent: '*',
      action: 'delete',
      resource: '**',
    });

    assert.equal(guard.policy.rules.length, 1);
    assert.equal(guard.policy.rules[0].id, 'safe-rule');

    // Attempting to mutate guard.policy directly throws TypeError
    assert.throws(() => {
      guard.policy.name = 'tampered';
    }, TypeError);
  });
});

describe('Milestone P2.3.3: isCompiledPolicy() Branding & Cryptographic Integrity', () => {
  it('returns false for primitives, null, undefined, or arrays', () => {
    assert.equal(isCompiledPolicy(null), false);
    assert.equal(isCompiledPolicy(undefined), false);
    assert.equal(isCompiledPolicy('policy-string'), false);
    assert.equal(isCompiledPolicy(123), false);
    assert.equal(isCompiledPolicy([]), false);
  });

  it('returns false for unbranded objects with .hash', () => {
    assert.equal(
      isCompiledPolicy({
        hash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        rules: [],
      }),
      false
    );
  });

  it('returns false for branded but unfrozen objects', () => {
    const obj = {
      [COMPILED_POLICY_BRAND]: true,
      name: 'unfrozen',
      version: '1.0',
      defaultEffect: 'DENY',
      rules: [],
      hash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    };
    assert.equal(isCompiledPolicy(obj), false);
  });

  it('returns false when hash does not match canonical SHA-256 of policy structure', () => {
    const forged = Object.freeze({
      [COMPILED_POLICY_BRAND]: true,
      name: 'forged',
      version: '1.0',
      defaultEffect: 'DENY',
      rules: [],
      hash: '0000000000000000000000000000000000000000000000000000000000000000',
    });
    assert.equal(isCompiledPolicy(forged), false);
  });
});

describe('Milestone P2.3.3: Capability Nonce, Constraints, and TTL Strictness', () => {
  const POLICY = compilePolicy({
    name: 'test-cap-policy',
    version: '1.0',
    defaultEffect: 'DENY',
    rules: [
      {
        id: 'r1',
        effect: 'ALLOW',
        agent: 'test-agent',
        action: 'write',
        resource: 'data/**',
        constraints: {
          absolute_max_size: '10MB',
          max_objects: 5,
        },
      },
    ],
  });

  it('rejects NaN, Infinity, -Infinity, and non-positive numbers for ttlSeconds in issueCapability', () => {
    const req = { action: 'write', resource: 'data/file.txt', size: '1MB', count: 1 };
    const ctx = { agentId: 'test-agent' };
    const guard = createGuard({ policy: POLICY, agent: 'test-agent' });
    const decision = guard.evaluate(req, ctx);

    // NaN
    assert.throws(
      () => issueCapability({ decision, request: req, context: ctx, options: { ttlSeconds: NaN, signingKey: SIGNING_KEY } }),
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'INVALID_TTL');
        return true;
      }
    );

    // Infinity
    assert.throws(
      () => issueCapability({ decision, request: req, context: ctx, options: { ttlSeconds: Infinity, signingKey: SIGNING_KEY } }),
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'INVALID_TTL');
        return true;
      }
    );

    // -Infinity
    assert.throws(
      () => issueCapability({ decision, request: req, context: ctx, options: { ttlSeconds: -Infinity, signingKey: SIGNING_KEY } }),
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'INVALID_TTL');
        return true;
      }
    );

    // Non-positive (0 or negative)
    assert.throws(
      () => issueCapability({ decision, request: req, context: ctx, options: { ttlSeconds: 0, signingKey: SIGNING_KEY } }),
      err => {
        assert.ok(err instanceof CapabilitySecurityError);
        assert.equal(err.code, 'INVALID_TTL');
        return true;
      }
    );
  });

  it('enforces exact 32-character hexadecimal nonce in verifyCapability (MALFORMED_NONCE)', () => {
    const req = { action: 'write', resource: 'data/file.txt', size: '1MB', count: 1 };
    const ctx = { agentId: 'test-agent' };
    const guard = createGuard({ policy: POLICY, agent: 'test-agent' });
    const decision = guard.evaluate(req, ctx);
    const validCap = issueCapability({ decision, request: req, context: ctx, options: { signingKey: SIGNING_KEY } });

    // 16 chars (too short)
    const shortCap = { ...validCap, nonce: '0123456789abcdef' };
    const resShort = verifyCapability(shortCap, POLICY, req, ctx, { signingKey: SIGNING_KEY });
    assert.equal(resShort.valid, false);
    assert.equal(resShort.code, 'MALFORMED_NONCE');

    // 40 chars (too long)
    const longCap = { ...validCap, nonce: '0123456789abcdef0123456789abcdef01234567' };
    const resLong = verifyCapability(longCap, POLICY, req, ctx, { signingKey: SIGNING_KEY });
    assert.equal(resLong.valid, false);
    assert.equal(resLong.code, 'MALFORMED_NONCE');

    // Exactly 32 hex chars passes nonce check
    assert.equal(/^[0-9a-f]{32}$/i.test(validCap.nonce), true);
  });

  it('strictly validates capability constraints fields (MALFORMED_CONSTRAINTS)', () => {
    const req = { action: 'write', resource: 'data/file.txt', size: '1MB', count: 1 };
    const ctx = { agentId: 'test-agent' };
    const guard = createGuard({ policy: POLICY, agent: 'test-agent' });
    const decision = guard.evaluate(req, ctx);
    const validCap = issueCapability({ decision, request: req, context: ctx, options: { signingKey: SIGNING_KEY } });

    // Negative maxBytes
    const badBytes = {
      ...validCap,
      constraints: { ...validCap.constraints, maxBytes: -100 },
    };
    const resBytes = verifyCapability(badBytes, POLICY, req, ctx, { signingKey: SIGNING_KEY });
    assert.equal(resBytes.valid, false);
    assert.equal(resBytes.code, 'MALFORMED_CONSTRAINTS');

    // Negative maxObjects
    const badObjects = {
      ...validCap,
      constraints: { ...validCap.constraints, maxObjects: -1 },
    };
    const resObjects = verifyCapability(badObjects, POLICY, req, ctx, { signingKey: SIGNING_KEY });
    assert.equal(resObjects.valid, false);
    assert.equal(resObjects.code, 'MALFORMED_CONSTRAINTS');

    // Non-boolean requireSnapshot
    const badSnapshot = {
      ...validCap,
      constraints: { ...validCap.constraints, requireSnapshot: 'true' },
    };
    const resSnapshot = verifyCapability(badSnapshot, POLICY, req, ctx, { signingKey: SIGNING_KEY });
    assert.equal(resSnapshot.valid, false);
    assert.equal(resSnapshot.code, 'MALFORMED_CONSTRAINTS');

    // Non-boolean dryRunOnly
    const badDryRun = {
      ...validCap,
      constraints: { ...validCap.constraints, dryRunOnly: 1 },
    };
    const resDryRun = verifyCapability(badDryRun, POLICY, req, ctx, { signingKey: SIGNING_KEY });
    assert.equal(resDryRun.valid, false);
    assert.equal(resDryRun.code, 'MALFORMED_CONSTRAINTS');
  });
});

describe('Milestone P2.3.3: parseByteSize() Safe Integer Range Defense', () => {
  it('throws TypeError when byte size exceeds safe integer range (Number.MAX_SAFE_INTEGER)', () => {
    // 10,000,000 TB exceeds 2^53 - 1
    assert.throws(
      () => parseByteSize('10000000TB'),
      err => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /exceeds safe integer range/);
        return true;
      }
    );

    // Number greater than MAX_SAFE_INTEGER
    assert.throws(
      () => parseByteSize(Number.MAX_SAFE_INTEGER + 100),
      err => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /safe non-negative integer/);
        return true;
      }
    );
  });

  it('permits byte sizes within safe integer range', () => {
    assert.equal(parseByteSize('50TB'), 50 * (1000 ** 4));
    assert.equal(parseByteSize('4096TiB'), 4096 * (1024 ** 4));
  });
});
