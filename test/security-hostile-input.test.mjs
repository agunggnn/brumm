/**
 * @file test/security-hostile-input.test.mjs
 * Security regression test suite for hostile inputs, identity boundaries,
 * policy compiler hardening, and YAML parser defenses (Milestones P2.1 & P2.2).
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DecisionOutcome,
  PolicyValidationError,
  compilePolicy,
  createGuard,
  evaluatePolicy,
  normalizeActionRequest,
  parseYamlSubset,
} from '../src/index.mjs';

describe('Hostile Input Defense: Strict Request Booleans', () => {
  it('rejects string "false" for hasSnapshot and fails closed to DENY', () => {
    const policy = compilePolicy({
      name: 'bool-policy',
      rules: [
        {
          id: 'cleanup-rule',
          effect: 'ALLOW',
          agent: 'cleanup-agent',
          action: 'delete',
          resource: 'backup/**',
          constraints: { require_snapshot: true },
        },
      ],
    });

    // Caller attempts boolean evasion by passing string "false"
    const decision = evaluatePolicy(
      policy,
      {
        action: 'delete',
        resource: 'backup/item',
        hasSnapshot: 'false',
      },
      { agentId: 'cleanup-agent' }
    );

    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Field "hasSnapshot" must be a boolean/);
  });

  it('rejects string "true" for isDryRun and fails closed to DENY', () => {
    assert.throws(
      () =>
        normalizeActionRequest({
          action: 'delete',
          resource: 'backup/item',
          isDryRun: 'true',
        }),
      TypeError
    );
  });

  it('rejects numeric 0 and 1 for boolean fields', () => {
    assert.throws(
      () =>
        normalizeActionRequest({
          action: 'delete',
          resource: 'backup/item',
          snapshot: 1,
        }),
      TypeError
    );

    assert.throws(
      () =>
        normalizeActionRequest({
          action: 'delete',
          resource: 'backup/item',
          dryRun: 0,
        }),
      TypeError
    );
  });

  it('accepts genuine boolean true/false values', () => {
    const req1 = normalizeActionRequest({
      action: 'delete',
      resource: 'backup/item',
      hasSnapshot: true,
      isDryRun: false,
    });
    assert.equal(req1.hasSnapshot, true);
    assert.equal(req1.isDryRun, false);

    const req2 = normalizeActionRequest({
      action: 'delete',
      resource: 'backup/item',
      snapshot: false,
      dryRun: true,
    });
    assert.equal(req2.hasSnapshot, false);
    assert.equal(req2.isDryRun, true);
  });
});

describe('Hostile Input Defense: Strict Object Count & Blast Radius', () => {
  const countPolicy = compilePolicy({
    name: 'count-policy',
    rules: [
      {
        id: 'bulk-rule',
        effect: 'ALLOW',
        agent: 'cleanup-agent',
        action: 'delete',
        resource: 'bulk/**',
        constraints: {
          max_objects: 100,
        },
      },
    ],
  });

  it('DENIES when count is negative', () => {
    const decision = evaluatePolicy(
      countPolicy,
      { action: 'delete', resource: 'bulk/items', count: -1 },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Invalid requested object count/);
  });

  it('DENIES when count is a floating point number', () => {
    const decision = evaluatePolicy(
      countPolicy,
      { action: 'delete', resource: 'bulk/items', count: 1.5 },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Must be a safe non-negative integer/);
  });

  it('DENIES when count is NaN, Infinity, or -Infinity', () => {
    for (const hostileValue of [NaN, Infinity, -Infinity]) {
      const decision = evaluatePolicy(
        countPolicy,
        { action: 'delete', resource: 'bulk/items', count: hostileValue },
        { agentId: 'cleanup-agent' }
      );
      assert.equal(decision.outcome, DecisionOutcome.DENY);
    }
  });

  it('DENIES when count is an unsafe integer beyond safe integer bounds', () => {
    const decision = evaluatePolicy(
      countPolicy,
      { action: 'delete', resource: 'bulk/items', count: '99999999999999999999999999' },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Exceeds safe integer range/);
  });

  it('correctly accepts explicit 0 count', () => {
    const decision = evaluatePolicy(
      countPolicy,
      { action: 'delete', resource: 'bulk/items', count: 0 },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });
});

describe('Hostile Input Defense: Missing Measurements Fail-Closed', () => {
  const boundedPolicy = compilePolicy({
    name: 'bounded-policy',
    rules: [
      {
        id: 'size-and-object-bounded',
        effect: 'ALLOW',
        agent: 'cleanup-agent',
        action: 'delete',
        resource: 'backup/**',
        constraints: {
          absolute_max_size: '50GB',
          max_objects: 100,
        },
      },
      {
        id: 'size-only-bounded',
        effect: 'ALLOW',
        agent: 'cleanup-agent',
        action: 'archive',
        resource: 'archive/**',
        constraints: {
          absolute_max_size: '50GB',
        },
      },
      {
        id: 'unbounded-read',
        effect: 'ALLOW',
        agent: '*',
        action: 'read',
        resource: '**',
      },
    ],
  });

  it('DENIES when rule bounds object count but request omits count', () => {
    const decision = evaluatePolicy(
      boundedPolicy,
      { action: 'delete', resource: 'backup/files', size: '10GB' },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /enforces object count limits, but no object count was provided/);
  });

  it('DENIES when rule bounds size but request omits size', () => {
    const decision = evaluatePolicy(
      boundedPolicy,
      { action: 'archive', resource: 'archive/files' },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /enforces data size limits, but no data size was provided/);
  });

  it('DENIES when rule bounds both and request omits both', () => {
    const decision = evaluatePolicy(
      boundedPolicy,
      { action: 'delete', resource: 'backup/files' },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
  });

  it('ALLOWS when rule does not bound measurements and request omits them', () => {
    const decision = evaluatePolicy(
      boundedPolicy,
      { action: 'read', resource: 'public/doc.txt' },
      { agentId: 'cleanup-agent' }
    );
    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });
});

describe('Compiler & Engine Hardening: Zero-Valued Limits', () => {
  const zeroLimitPolicy = compilePolicy({
    name: 'zero-policy',
    rules: [
      {
        id: 'zero-objects-rule',
        effect: 'ALLOW',
        agent: 'test-agent',
        action: 'touch',
        resource: 'zone-a/**',
        constraints: {
          max_objects: 0,
        },
      },
      {
        id: 'zero-size-rule',
        effect: 'ALLOW',
        agent: 'test-agent',
        action: 'create-empty',
        resource: 'zone-b/**',
        constraints: {
          absolute_max_size: '0B',
        },
      },
    ],
  });

  it('enforces max_objects: 0 strictly (ALLOW for 0, DENY for 1)', () => {
    const allowDecision = evaluatePolicy(
      zeroLimitPolicy,
      { action: 'touch', resource: 'zone-a/test', count: 0 },
      { agentId: 'test-agent' }
    );
    assert.equal(allowDecision.outcome, DecisionOutcome.ALLOW);

    const denyDecision = evaluatePolicy(
      zeroLimitPolicy,
      { action: 'touch', resource: 'zone-a/test', count: 1 },
      { agentId: 'test-agent' }
    );
    assert.equal(denyDecision.outcome, DecisionOutcome.DENY);
    assert.match(denyDecision.reasons[0], /exceeds absolute maximum limit \(0\)/);
  });

  it('enforces absolute_max_size: "0B" strictly (ALLOW for 0, DENY for 1)', () => {
    const allowDecision = evaluatePolicy(
      zeroLimitPolicy,
      { action: 'create-empty', resource: 'zone-b/test', size: 0 },
      { agentId: 'test-agent' }
    );
    assert.equal(allowDecision.outcome, DecisionOutcome.ALLOW);

    const denyDecision = evaluatePolicy(
      zeroLimitPolicy,
      { action: 'create-empty', resource: 'zone-b/test', size: 1 },
      { agentId: 'test-agent' }
    );
    assert.equal(denyDecision.outcome, DecisionOutcome.DENY);
    assert.match(denyDecision.reasons[0], /exceeds absolute maximum limit \(0 bytes\)/);
  });
});

describe('Identity Hardening: Context Trust Boundaries', () => {
  const guard = createGuard({
    policy: {
      name: 'boundary-policy',
      rules: [
        {
          id: 'admin-prod-rule',
          effect: 'ALLOW',
          agent: 'admin',
          action: 'delete',
          resource: '**',
          environment: 'production',
        },
        {
          id: 'worker-staging-rule',
          effect: 'ALLOW',
          agent: 'worker-agent',
          action: 'delete',
          resource: '**',
          environment: 'staging',
        },
      ],
    },
    agent: 'worker-agent',
    environment: 'production',
  });

  it('blocks untrusted caller from overriding bound environment to bypass rules', () => {
    // Worker in production cannot claim to be in staging
    const decision = guard.evaluate(
      { action: 'delete', resource: 'app/data' },
      { environment: 'staging' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Security context violation/);
    assert.match(decision.reasons[0], /Untrusted caller attempted to override bound environment/);
  });

  it('blocks untrusted caller from overriding bound agentId to escalate privileges', () => {
    // Worker cannot claim to be admin
    const decision = guard.evaluate(
      { action: 'delete', resource: 'app/data' },
      { agentId: 'admin' }
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Security context violation/);
    assert.match(decision.reasons[0], /Untrusted caller attempted to override bound agent/);
  });

  it('blocks string context override from replacing bound agentId', () => {
    const decision = guard.evaluate(
      { action: 'delete', resource: 'app/data' },
      'admin'
    );
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Security context violation/);
  });

  it('permits dynamic turn metadata and taskUid within bound context', () => {
    const decision = guard.evaluate(
      { action: 'delete', resource: 'app/data' },
      { taskUid: 'task_turn_456', metadata: { source: 'slack' } }
    );
    // Evaluates with bound worker in production (no rule permits worker delete in production -> DENY by policy, not context violation)
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Default-deny/);
  });

  it('permits dynamic environment and agent override when configured as gateway', () => {
    const gatewayGuard = createGuard({
      policy: {
        name: 'gateway-policy',
        rules: [
          {
            id: 'staging-rule',
            effect: 'ALLOW',
            agent: '*',
            action: 'delete',
            resource: '**',
            environment: 'staging',
          },
        ],
      },
      agent: 'broker',
      environment: 'production',
      trustBoundary: 'gateway',
    });

    const decision = gatewayGuard.evaluate(
      { action: 'delete', resource: 'app/data' },
      { environment: 'staging' }
    );
    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });
});

describe('Policy Compiler Hardening: Integrity Checks', () => {
  it('rejects duplicate rule IDs at compile time', () => {
    assert.throws(
      () =>
        compilePolicy({
          name: 'dup-policy',
          rules: [
            { id: 'rule-x', effect: 'DENY', action: 'read', resource: '/a' },
            { id: 'rule-x', effect: 'DENY', action: 'read', resource: '/b' },
          ],
        }),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /Duplicate rule ID detected: "rule-x"/);
        return true;
      }
    );
  });

  it('rejects effect ALLOW with critical: true at compile time', () => {
    assert.throws(
      () =>
        compilePolicy({
          name: 'bad-crit-policy',
          rules: [
            {
              id: 'crit-allow',
              effect: 'ALLOW',
              agent: '*',
              action: 'delete',
              resource: '/data/*',
              critical: true,
            },
          ],
        }),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /cannot combine critical asset protection/);
        return true;
      }
    );
  });

  it('rejects effect CONSTRAIN with critical: true at compile time', () => {
    assert.throws(
      () =>
        compilePolicy({
          name: 'bad-crit-policy',
          rules: [
            {
              id: 'crit-constrain',
              effect: 'CONSTRAIN',
              agent: '*',
              action: 'delete',
              resource: '/data/*',
              isCriticalProtection: true,
            },
          ],
        }),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /cannot combine critical asset protection/);
        return true;
      }
    );
  });

  it('rejects ALLOW rule missing explicit agent pattern', () => {
    assert.throws(
      () =>
        compilePolicy({
          name: 'missing-agent-policy',
          rules: [
            {
              id: 'no-agent',
              effect: 'ALLOW',
              action: 'read',
              resource: '/data/*',
            },
          ],
        }),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /must explicitly declare an "agent" pattern/);
        return true;
      }
    );
  });

  it('rejects ALLOW rule missing explicit resource pattern', () => {
    assert.throws(
      () =>
        compilePolicy({
          name: 'missing-resource-policy',
          rules: [
            {
              id: 'no-resource',
              effect: 'ALLOW',
              agent: 'worker',
              action: 'read',
            },
          ],
        }),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /must explicitly declare a "resource" pattern/);
        return true;
      }
    );
  });

  it('rejects invalid numeric constraints at compile time (NaN, negative, float)', () => {
    assert.throws(
      () =>
        compilePolicy({
          name: 'nan-policy',
          rules: [
            {
              id: 'r1',
              effect: 'ALLOW',
              agent: '*',
              action: 'read',
              resource: '**',
              constraints: { max_objects: NaN },
            },
          ],
        }),
      PolicyValidationError
    );

    assert.throws(
      () =>
        compilePolicy({
          name: 'float-policy',
          rules: [
            {
              id: 'r1',
              effect: 'ALLOW',
              agent: '*',
              action: 'read',
              resource: '**',
              constraints: { max_objects: 10.5 },
            },
          ],
        }),
      PolicyValidationError
    );
  });
});

describe('YAML Parser Hardening: Attacks & Syntax Defense', () => {
  it('preserves "#" character inside single and double quotes', () => {
    const yaml = `
name: "policy#with#hashes"
description: 'test # inside single quotes'
rules:
  - id: "rule#1"
    effect: ALLOW
    agent: "*"
    action: "read#write"
    resource: "/data/#prod" # this is an actual trailing comment
`;
    const parsed = parseYamlSubset(yaml);
    assert.equal(parsed.name, 'policy#with#hashes');
    assert.equal(parsed.description, 'test # inside single quotes');
    assert.equal(parsed.rules[0].id, 'rule#1');
    assert.equal(parsed.rules[0].action, 'read#write');
    assert.equal(parsed.rules[0].resource, '/data/#prod');
  });

  it('rejects duplicate keys in mapping', () => {
    const yaml = `
name: first-name
name: duplicate-name
`;
    assert.throws(
      () => parseYamlSubset(yaml),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /Duplicate YAML key detected in mapping: "name"/);
        return true;
      }
    );
  });

  it('rejects duplicate keys in nested mapping inside sequence', () => {
    const yaml = `
rules:
  - id: r1
    action: read
    action: delete
`;
    assert.throws(
      () => parseYamlSubset(yaml),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /Duplicate YAML key detected in mapping: "action"/);
        return true;
      }
    );
  });

  it('rejects prototype pollution keys (__proto__, constructor, prototype)', () => {
    for (const forbiddenKey of ['__proto__', 'constructor', 'prototype']) {
      const yaml = `
${forbiddenKey}:
  polluted: true
`;
      assert.throws(
        () => parseYamlSubset(yaml),
        err => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /forbidden prototype-polluting key/);
          return true;
        }
      );
    }
  });

  it('rejects tabs used for indentation', () => {
    const yaml = "name: tab-test\n\trules:\n\t  - id: r1";
    assert.throws(
      () => parseYamlSubset(yaml),
      err => {
        assert.ok(err instanceof PolicyValidationError);
        assert.match(err.message, /Tabs are not allowed for indentation/);
        return true;
      }
    );
  });
});
