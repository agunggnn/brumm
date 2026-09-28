/**
 * @file test/policy-engine.test.mjs
 * Unit tests for the Deterministic Policy Engine and Honest Mistake scenario.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DecisionOutcome } from '../src/core/decision.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const SAMPLE_POLICY = compilePolicy({
  name: 'test-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'critical-root-defense',
      effect: 'DENY',
      isCriticalProtection: true,
      agent: '*',
      action: 'delete',
      resource: '/data/*',
      environment: 'production',
      reasons: ['Root-level wiping forbidden in production'],
    },
    {
      id: 'cleanup-safe-rule',
      effect: 'ALLOW',
      agent: 'cleanup-agent',
      action: 'delete',
      resource: 'backup-prod/**',
      environment: 'production',
      constraints: {
        max_size: '50GB',
        require_snapshot: true,
        require_approval_above: '50GB',
      },
    },
    {
      id: 'general-read',
      effect: 'ALLOW',
      agent: '*',
      action: 'read',
      resource: '**',
      environment: '*',
    },
  ],
});

describe('Brumm Policy Engine', () => {
  it('ALLOWS safe operation within bounds with snapshot', () => {
    const request = {
      action: 'delete',
      resource: 'backup-prod/old-logs',
      size: '20GB',
      hasSnapshot: true,
    };
    const context = {
      agentId: 'cleanup-agent',
      environment: 'production',
    };

    const decision = evaluatePolicy(SAMPLE_POLICY, request, context);
    assert.equal(decision.outcome, DecisionOutcome.ALLOW);
    assert.equal(decision.allowed, true);
    assert.equal(decision.matchedRule, 'cleanup-safe-rule');
  });

  it('ESCALATES when requested size exceeds autonomous limit (The Honest Mistake Scenario)', () => {
    // Agent was asked to "free up disk space" and tries to delete 700GB
    const request = {
      action: 'delete',
      resource: 'backup-prod/cluster-archive',
      size: '700GB',
      hasSnapshot: true,
    };
    const context = {
      agentId: 'cleanup-agent',
      environment: 'production',
    };

    const decision = evaluatePolicy(SAMPLE_POLICY, request, context);
    assert.equal(decision.outcome, DecisionOutcome.ESCALATE);
    assert.equal(decision.requiresApproval, true);
    assert.match(decision.reasons[0], /exceeds autonomous approval threshold/);
  });

  it('CONSTRAINS with suggested snapshot transform when snapshot is missing', () => {
    const request = {
      action: 'delete',
      resource: 'backup-prod/temp-files',
      size: '10GB',
      hasSnapshot: false,
    };
    const context = {
      agentId: 'cleanup-agent',
      environment: 'production',
    };

    const decision = evaluatePolicy(SAMPLE_POLICY, request, context);
    assert.equal(decision.outcome, DecisionOutcome.CONSTRAIN);
    assert.equal(decision.isConstrained, true);
    assert.ok(decision.suggestedTransform);
    assert.equal(decision.suggestedTransform.step, 'SNAPSHOT');
  });

  it('DENIES critical asset operations via critical resource protection', () => {
    const request = {
      action: 'delete',
      resource: '/data/prod-db',
    };
    const context = {
      agentId: 'cleanup-agent',
      environment: 'production',
    };

    const decision = evaluatePolicy(SAMPLE_POLICY, request, context);
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.equal(decision.isDenied, true);
    assert.match(decision.reasons[0], /Root-level wiping forbidden/);
  });

  it('enforces DEFAULT_DENY when no rule matches', () => {
    const request = {
      action: 'deploy',
      resource: 'k8s/cluster-admin',
    };
    const context = {
      agentId: 'cleanup-agent',
      environment: 'production',
    };

    const decision = evaluatePolicy(SAMPLE_POLICY, request, context);
    assert.equal(decision.outcome, DecisionOutcome.DENY);
    assert.match(decision.reasons[0], /Default-deny/);
  });

  it('neutralizes resource substitution traversal attempts', () => {
    // Attempting traversal to hit root /data via allowed backup-prod path
    const request = {
      action: 'delete',
      resource: 'backup-prod/../../data/prod-db',
      hasSnapshot: true,
    };
    const context = {
      agentId: 'cleanup-agent',
      environment: 'production',
    };

    const decision = evaluatePolicy(SAMPLE_POLICY, request, context);
    // Path traversal either gets rejected during normalization or resolves outside backup-prod
    assert.equal(decision.outcome, DecisionOutcome.DENY);
  });
});
