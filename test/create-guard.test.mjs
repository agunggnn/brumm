/**
 * @file test/create-guard.test.mjs
 * Unit tests for createGuard programmatic interface.
 */

import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import { DecisionOutcome, createGuard } from '../src/index.mjs';

describe('createGuard API', () => {
  it('creates guard from policy file path and evaluates requests', () => {
    const policyPath = resolve(process.cwd(), 'brumm-policy.yaml');
    const guard = createGuard({
      policy: policyPath,
      agent: 'cleanup-agent',
      environment: 'production',
    });

    assert.ok(guard.policyHash);
    assert.equal(typeof guard.policyHash, 'string');
    assert.equal(guard.policyHash.length, 64);

    // Test safe delete with snapshot
    const decision = guard.evaluate({
      action: 'delete',
      resource: 'backup-prod/test',
      size: '10GB',
      hasSnapshot: true,
    });

    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
    assert.equal(decision.allowed, true);
  });

  it('evaluates with context override', () => {
    const policyPath = resolve(process.cwd(), 'brumm-policy.yaml');
    const guard = createGuard({
      policy: policyPath,
      agent: 'cleanup-agent',
      environment: 'production',
    });

    // Override environment to staging
    const decision = guard.evaluate(
      {
        action: 'arbitrary-action',
        resource: 'any-resource',
      },
      { environment: 'staging' }
    );

    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });
});
