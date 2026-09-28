/**
 * @file test/security-integrity.test.mjs
 * Security regression tests verifying hash integrity, deep immutability,
 * schema validation, blast radius enforcement, and URI authority protection.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { canonicalizeResource } from '../src/core/canonical.mjs';
import {
  DecisionOutcome,
  parseByteSize,
} from '../src/core/decision.mjs';
import {
  PolicyValidationError,
  ResourceCanonicalizationError,
} from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

describe('Security Regression 1: Canonical Policy Hash Integrity', () => {
  it('produces identical hash regardless of top-level and nested key ordering', () => {
    const policyA = {
      name: 'guard',
      version: '1.0',
      rules: [
        {
          id: 'rule-1',
          effect: 'ALLOW',
          agent: '*',
          action: 'delete',
          resource: 'backup/**',
          constraints: { max_size: '50GB', require_snapshot: true },
        },
      ],
    };

    const policyB = {
      version: '1.0',
      name: 'guard',
      rules: [
        {
          constraints: { require_snapshot: true, max_size: '50GB' },
          resource: 'backup/**',
          agent: '*',
          action: 'delete',
          effect: 'ALLOW',
          id: 'rule-1',
        },
      ],
    };

    const compiledA = compilePolicy(policyA);
    const compiledB = compilePolicy(policyB);

    assert.equal(compiledA.hash, compiledB.hash);
    assert.equal(compiledA.hash.length, 64);
  });

  it('produces different hash when rule effect changes (ALLOW -> DENY)', () => {
    const base = {
      name: 'guard',
      rules: [{ id: 'r1', agent: '*', action: 'delete', resource: 'backup/**', effect: 'ALLOW' }],
    };
    const modified = {
      name: 'guard',
      rules: [{ id: 'r1', agent: '*', action: 'delete', resource: 'backup/**', effect: 'DENY' }],
    };

    const hashA = compilePolicy(base).hash;
    const hashB = compilePolicy(modified).hash;
    assert.notEqual(hashA, hashB);
  });

  it('produces different hash when rule resource scope expands', () => {
    const base = {
      name: 'guard',
      rules: [{ id: 'r1', agent: '*', action: 'delete', resource: 'backup/**', effect: 'ALLOW' }],
    };
    const modified = {
      name: 'guard',
      rules: [{ id: 'r1', agent: '*', action: 'delete', resource: '**', effect: 'ALLOW' }],
    };

    assert.notEqual(compilePolicy(base).hash, compilePolicy(modified).hash);
  });

  it('produces different hash when nested constraint changes', () => {
    const base = {
      name: 'guard',
      rules: [{ id: 'r1', agent: '*', action: 'delete', resource: 'backup/**', effect: 'ALLOW', constraints: { max_size: '50GB' } }],
    };
    const modified = {
      name: 'guard',
      rules: [{ id: 'r1', agent: '*', action: 'delete', resource: 'backup/**', effect: 'ALLOW', constraints: { max_size: '500GB' } }],
    };

    assert.notEqual(compilePolicy(base).hash, compilePolicy(modified).hash);
  });
});

describe('Security Regression 2: Deep Immutability of Compiled Policy', () => {
  it('throws TypeError when attempting to mutate compiled policy or nested rules', () => {
    const compiled = compilePolicy({
      name: 'immutable-policy',
      rules: [
        {
          id: 'r1',
          effect: 'DENY',
          action: 'delete',
          resource: '/data/*',
          constraints: { max_size: '50GB' },
          reasons: ['Root deletion denied'],
        },
      ],
    });

    // 1. Mutate rule property
    assert.throws(
      () => {
        compiled.rules[0].effect = 'ALLOW';
      },
      TypeError
    );

    // 2. Mutate nested constraint
    assert.throws(
      () => {
        compiled.rules[0].constraints.absoluteMaxSize = 999999;
      },
      TypeError
    );

    // 3. Mutate reasons array
    assert.throws(
      () => {
        compiled.rules[0].reasons.push('attacker-injected-reason');
      },
      TypeError
    );

    // 4. Mutate rules array
    assert.throws(
      () => {
        compiled.rules.push({ id: 'injected', effect: 'ALLOW' });
      },
      TypeError
    );
  });
});

describe('Security Regression 3: Invalid Policy Effect & Schema Typo Rejection', () => {
  it('rejects invalid effect at compile time (fail-closed)', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'bad-effect',
          rules: [{ id: 'r1', effect: 'INVALID_EFFECT', action: 'read', resource: '**' }],
        });
      },
      PolicyValidationError
    );
  });

  it('rejects invalid defaultEffect at compile time', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'bad-default',
          defaultEffect: 'MAYBE_ALLOW',
          rules: [],
        });
      },
      PolicyValidationError
    );
  });

  it('rejects unknown typo field in rule (effcet instead of effect)', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'typo-policy',
          rules: [{ id: 'r1', effcet: 'DENY', action: 'delete', resource: '**' }],
        });
      },
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /Unknown field "effcet"/);
        return true;
      }
    );
  });

  it('rejects unknown constraint field', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'typo-constraint',
          rules: [{ id: 'r1', action: 'delete', resource: '**', constraints: { unknown_limit: 50 } }],
        });
      },
      PolicyValidationError
    );
  });
});

describe('Security Regression 4: Blast Radius Object Count Enforcement', () => {
  it('DENIES when requestedCount exceeds absolute_max_objects', () => {
    const policy = compilePolicy({
      name: 'object-cap-policy',
      rules: [
        {
          id: 'cleanup-files',
          effect: 'ALLOW',
          agent: 'cleanup-agent',
          action: 'delete',
          resource: 'backup/**',
          constraints: { max_objects: 100 },
        },
      ],
    });

    // Requesting 1,000,000 objects
    const decision = evaluatePolicy(
      policy,
      { action: 'delete', resource: 'backup/files', count: 1_000_000 },
      { agentId: 'cleanup-agent' }
    );

    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.equal(decision.isDenied, true);
    assert.match(decision.reasons[0], /exceeds absolute maximum limit \(100\)/);
  });

  it('ESCALATES when requestedCount exceeds approval threshold but within absolute limit', () => {
    const policy = compilePolicy({
      name: 'tiered-objects-policy',
      rules: [
        {
          id: 'batch-delete',
          effect: 'ALLOW',
          agent: 'cleanup-agent',
          action: 'delete',
          resource: 'temp/**',
          constraints: {
            approval_above_objects: 50,
            absolute_max_objects: 500,
          },
        },
      ],
    });

    // 30 objects -> ALLOW
    const dec1 = evaluatePolicy(
      policy,
      { action: 'delete', resource: 'temp/logs', count: 30 },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(dec1.outcome, DecisionOutcome.ALLOW);

    // 150 objects -> ESCALATE
    const dec2 = evaluatePolicy(
      policy,
      { action: 'delete', resource: 'temp/logs', count: 150 },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(dec2.outcome, DecisionOutcome.ESCALATE);
    assert.match(dec2.reasons[0], /exceeds autonomous approval threshold \(50\)/);

    // 1000 objects -> DENY
    const dec3 = evaluatePolicy(
      policy,
      { action: 'delete', resource: 'temp/logs', count: 1000 },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(dec3.outcome, DecisionOutcome.DENY);
    assert.match(dec3.reasons[0], /exceeds absolute maximum limit \(500\)/);
  });
});

describe('Security Regression 5: Strict Byte Size Parser & Unit Disambiguation', () => {
  it('correctly calculates decimal (SI) byte sizes', () => {
    assert.equal(parseByteSize('50KB'), 50 * 1000);
    assert.equal(parseByteSize('50MB'), 50 * 1000 * 1000);
    assert.equal(parseByteSize('50GB'), 50 * 1000 * 1000 * 1000);
    assert.equal(parseByteSize('1TB'), 1000 * 1000 * 1000 * 1000);
  });

  it('correctly calculates binary (IEC) byte sizes', () => {
    assert.equal(parseByteSize('50KiB'), 50 * 1024);
    assert.equal(parseByteSize('50MiB'), 50 * 1024 * 1024);
    assert.equal(parseByteSize('50GiB'), 50 * 1024 * 1024 * 1024);
    assert.equal(parseByteSize('1TiB'), 1024 * 1024 * 1024 * 1024);
  });

  it('throws TypeError on unrecognized unit (50FOOBAR)', () => {
    assert.throws(
      () => parseByteSize('50FOOBAR'),
      err => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /Invalid byte size unit "FOOBAR"/);
        return true;
      }
    );
  });

  it('throws TypeError on negative or invalid numbers', () => {
    assert.throws(() => parseByteSize(-100), TypeError);
    assert.throws(() => parseByteSize(''), TypeError);
  });
});

describe('Security Regression 6: Provider-Aware URI Authority Traversal Defense', () => {
  it('throws ResourceCanonicalizationError when traversal attempts to escape authority root in URI', () => {
    assert.throws(
      () => canonicalizeResource('s3://prod-bucket/../../other-bucket/secret'),
      ResourceCanonicalizationError
    );
  });

  it('preserves authority and resolves path correctly inside authority', () => {
    const res = canonicalizeResource('s3://prod-bucket/data/logs/../archive/file.csv');
    assert.equal(res.scheme, 's3');
    assert.equal(res.authority, 'prod-bucket');
    assert.equal(res.path, '/data/archive/file.csv');
    assert.equal(res.uri, 's3://prod-bucket/data/archive/file.csv');
  });

  it('supports AWS ARN canonicalization', () => {
    const res = canonicalizeResource('arn:aws:s3:::my-bucket/data/prod.db');
    assert.equal(res.scheme, 'arn');
    assert.equal(res.uri, 'arn:aws:s3:::my-bucket/data/prod.db');
  });
});

describe('Security Regression 7: Strict Constraint Value Validation', () => {
  it('rejects non-numeric string for max_objects ("abc")', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'bad-objects',
          rules: [{ id: 'r1', effect: 'ALLOW', constraints: { max_objects: 'abc' } }],
        });
      },
      PolicyValidationError
    );
  });

  it('rejects negative object counts', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'bad-objects',
          rules: [{ id: 'r1', effect: 'ALLOW', constraints: { max_objects: -10 } }],
        });
      },
      PolicyValidationError
    );
  });

  it('rejects non-boolean values for require_snapshot', () => {
    assert.throws(
      () => {
        compilePolicy({
          name: 'bad-bool',
          rules: [{ id: 'r1', effect: 'ALLOW', constraints: { require_snapshot: 'yes' } }],
        });
      },
      PolicyValidationError
    );
  });
});

describe('Security Regression 8: Fail-Closed Malformed Request Counts', () => {
  const policy = compilePolicy({
    name: 'test-pol',
    rules: [{ id: 'r1', effect: 'ALLOW', agent: '*', action: '*', resource: '**' }],
  });

  it('DENIES when count is negative', () => {
    const decision = evaluatePolicy(policy, { action: 'read', resource: '/data', count: -5 });
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.equal(decision.isDenied, true);
    assert.match(decision.reasons[0], /Invalid requested object count/);
  });

  it('DENIES when count is non-numeric string', () => {
    const decision = evaluatePolicy(policy, { action: 'read', resource: '/data', count: 'invalid' });
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Invalid requested object count/);
  });

  it('correctly parses digit string count ("1000")', () => {
    const countPolicy = compilePolicy({
      name: 'count-pol',
      rules: [{ id: 'r1', effect: 'ALLOW', agent: '*', action: '*', resource: '**', constraints: { max_objects: 500 } }],
    });
    const decision = evaluatePolicy(countPolicy, { action: 'read', resource: '/data', count: '1000' });
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /exceeds absolute maximum limit \(500\)/);
  });
});

describe('Security Regression 9: Fail-Closed Malformed Agent Context', () => {
  const policy = compilePolicy({
    name: 'test-pol',
    rules: [{ id: 'r1', effect: 'ALLOW', agent: '*', action: '*', resource: '**' }],
  });

  it('DENIES instead of throwing when context is null', () => {
    const decision = evaluatePolicy(policy, { action: 'read', resource: '/data' }, null);
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.equal(decision.isDenied, true);
    assert.match(decision.reasons[0], /Invalid or malformed request\/context/);
  });

  it('DENIES when context is an invalid primitive number', () => {
    const decision = evaluatePolicy(policy, { action: 'read', resource: '/data' }, 12345);
    assert.equal(decision.outcome, DecisionOutcome.DENY);
  });
});

describe('Security Regression 10: Percent-Encoded Path Traversal Protection', () => {
  it('detects and blocks %2e%2e traversal attempts escaping root', () => {
    assert.throws(
      () => canonicalizeResource('/var/%2e%2e/%2e%2e/etc/passwd'),
      ResourceCanonicalizationError
    );
  });

  it('detects and blocks double-encoded %252e%252e traversal', () => {
    assert.throws(
      () => canonicalizeResource('/var/%252e%252e/%252e%252e/etc/passwd'),
      ResourceCanonicalizationError
    );
  });

  it('detects encoded slashes and backslashes (%2f, %5c)', () => {
    assert.throws(
      () => canonicalizeResource('/var/%2e%2e%2f%2e%2e%5cetc%5cpasswd'),
      ResourceCanonicalizationError
    );
  });

  it('blocks encoded traversal in S3 URIs', () => {
    assert.throws(
      () => canonicalizeResource('s3://prod-bucket/%2e%2e/other-bucket'),
      ResourceCanonicalizationError
    );
  });
});

describe('Security Regression 11: Deep Immutability of Decision Objects', () => {
  const policy = compilePolicy({
    name: 'test-pol',
    rules: [{
      id: 'r1',
      effect: 'CONSTRAIN',
      agent: '*',
      action: 'delete',
      resource: '**',
      constraints: { require_snapshot: true },
    }],
  });

  it('throws TypeError when attempting to mutate returned decision object or constraints', () => {
    const decision = evaluatePolicy(policy, { action: 'delete', resource: '/data', snapshot: false });
    assert.equal(decision.outcome, DecisionOutcome.CONSTRAIN);

    assert.throws(
      () => {
        decision.outcome = DecisionOutcome.ALLOW;
      },
      TypeError
    );

    assert.throws(
      () => {
        decision.constraints.requireSnapshot = false;
      },
      TypeError
    );

    assert.throws(
      () => {
        decision.reasons.push('injected reason');
      },
      TypeError
    );
  });
});
