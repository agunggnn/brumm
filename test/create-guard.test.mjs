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
      count: 1,
      hasSnapshot: true,
    });

    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
    assert.equal(decision.allowed, true);
  });

  it('blocks untrusted environment escalation in strict mode by default', () => {
    const policyPath = resolve(process.cwd(), 'brumm-policy.yaml');
    const guard = createGuard({
      policy: policyPath,
      agent: 'cleanup-agent',
      environment: 'production',
    });

    // Untrusted override attempt to staging must be DENIED as a context violation
    const decision = guard.evaluate(
      {
        action: 'arbitrary-action',
        resource: 'any-resource',
      },
      { environment: 'staging' }
    );

    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Security context violation/);
  });

  it('permits dynamic context override when trustBoundary is configured as gateway', () => {
    const policyPath = resolve(process.cwd(), 'brumm-policy.yaml');
    const gatewayGuard = createGuard({
      policy: policyPath,
      agent: 'cleanup-agent',
      environment: 'production',
      trustBoundary: 'gateway',
    });

    // Gateway mode permits overriding environment dynamically
    const decision = gatewayGuard.evaluate(
      {
        action: 'arbitrary-action',
        resource: 'any-resource',
      },
      { environment: 'staging' }
    );

    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
  });
});
