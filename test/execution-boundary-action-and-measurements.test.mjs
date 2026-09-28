/**
 * @file test/execution-boundary-action-and-measurements.test.mjs
 * Security regression tests for Milestone P2.3.1:
 * Execution Boundary Hardening:
 * 1. Tool action binding (toolName === capability.action === verifiedRequest.action)
 * 2. Fail-closed capability bounds measurement enforcement (BYTE_MEASUREMENT_REQUIRED, OBJECT_MEASUREMENT_REQUIRED)
 * 3. Strict boolean signal validation in execute() (rejection of "false", "true", 0, 1)
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createExecutionGuard } from '../src/adapters/tool-adapter.mjs';
import { issueCapability, verifyCapability } from '../src/core/capability.mjs';
import { DecisionOutcome } from '../src/core/decision.mjs';
import { ExecutionSecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const SIGNING_KEY = 'test-signing-key-32-chars-minimum-safe!';

const ACTION_POLICY = compilePolicy({
  name: 'action-binding-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'allow-delete',
      effect: 'ALLOW',
      agent: 'ops-agent',
      action: 'delete',
      resource: 'data/**',
    },
    {
      id: 'allow-read',
      effect: 'ALLOW',
      agent: 'ops-agent',
      action: 'read',
      resource: 'data/**',
    },
  ],
});

describe('Milestone P2.3.1: Tool Action Binding at Execution Boundary', () => {
  const guard = {
    policy: ACTION_POLICY,
    evaluate: (req, ctx) => evaluatePolicy(ACTION_POLICY, req, ctx),
  };
  const executionGuard = createExecutionGuard({ guard, signingKey: SIGNING_KEY });

  it('succeeds when tool name, capability action, and request action all match', async () => {
    let executorInvoked = false;
    async function mockExecutor(params) {
      executorInvoked = true;
      return { status: 'DELETED' };
    }

    const request = { action: 'delete', resource: 'data/file.txt' };
    const context = { agentId: 'ops-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedDelete = executionGuard.protect('delete', mockExecutor);
    const res = await protectedDelete(
      { path: 'data/file.txt' },
      { capability, request, context }
    );

    assert.equal(res.status, 'DELETED');
    assert.equal(executorInvoked, true);
  });

  it('rejects execution when capability action differs from protected toolName (TOOL_ACTION_MISMATCH)', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'DELETED' };
    }

    // Capability was authorized ONLY for 'read'
    const readRequest = { action: 'read', resource: 'data/file.txt' };
    const context = { agentId: 'ops-agent' };
    const decision = guard.evaluate(readRequest, context);
    const readCapability = issueCapability({ decision, request: readRequest, context, options: { signingKey: SIGNING_KEY } });

    // Attacker attempts to use 'read' capability to invoke a 'delete' tool!
    const protectedDelete = executionGuard.protect('delete', mockExecutor);

    await assert.rejects(
      async () => {
        await protectedDelete(
          { path: 'data/file.txt' },
          { capability: readCapability, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'TOOL_ACTION_MISMATCH');
        assert.match(err.message, /tool action \("delete"\) does not match authorized capability action \("read"\)/);
        return true;
      }
    );

    // Verify rawExecutor was NEVER called
    assert.equal(executorInvoked, false);
  });

  it('rejects execution when caller passes request.action matching capability while toolName differs', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'DELETED' };
    }

    // Capability was authorized for 'read'
    const readRequest = { action: 'read', resource: 'data/file.txt' };
    const context = { agentId: 'ops-agent' };
    const decision = guard.evaluate(readRequest, context);
    const readCapability = issueCapability({ decision, request: readRequest, context, options: { signingKey: SIGNING_KEY } });

    // Attacker passes explicit request with action: 'read' to protected tool 'delete'
    const protectedDelete = executionGuard.protect('delete', mockExecutor);

    await assert.rejects(
      async () => {
        await protectedDelete(
          { path: 'data/file.txt' },
          { capability: readCapability, request: readRequest, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'TOOL_ACTION_MISMATCH');
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('rejects execution when capability and toolName match but request.action differs', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'DELETED' };
    }

    const deleteRequest = { action: 'delete', resource: 'data/file.txt' };
    const context = { agentId: 'ops-agent' };
    const decision = guard.evaluate(deleteRequest, context);
    const deleteCapability = issueCapability({ decision, request: deleteRequest, context, options: { signingKey: SIGNING_KEY } });

    const protectedDelete = executionGuard.protect('delete', mockExecutor);

    // Request tries to substitute action 'wipe'
    await assert.rejects(
      async () => {
        await protectedDelete(
          { path: 'data/file.txt' },
          { capability: deleteCapability, request: { action: 'wipe', resource: 'data/file.txt' }, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'TOOL_ACTION_MISMATCH');
        assert.match(err.message, /request action \("wipe"\) does not match tool action \("delete"\)/);
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('validates normal execution successfully through protected executor without explicit request', async () => {
    let executorInvoked = false;
    async function mockExecutor(params) {
      executorInvoked = true;
      return { status: 'OK', target: params.path };
    }

    const request = { action: 'delete', resource: 'data/file.txt' };
    const context = { agentId: 'ops-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedDelete = executionGuard.protect('delete', mockExecutor);
    const res = await protectedDelete({ path: 'data/file.txt' }, { capability, context });

    assert.equal(res.status, 'OK');
    assert.equal(executorInvoked, true);
  });
});

const MEASUREMENTS_POLICY = compilePolicy({
  name: 'measurements-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'bytes-limited-rule',
      effect: 'ALLOW',
      agent: 'storage-agent',
      action: 'store',
      resource: 'storage/bytes/**',
      constraints: {
        absolute_max_size: '50MB',
      },
    },
    {
      id: 'objects-limited-rule',
      effect: 'ALLOW',
      agent: 'storage-agent',
      action: 'batch',
      resource: 'storage/objects/**',
      constraints: {
        max_objects: 10,
      },
    },
    {
      id: 'both-limited-rule',
      effect: 'ALLOW',
      agent: 'storage-agent',
      action: 'transfer',
      resource: 'storage/both/**',
      constraints: {
        absolute_max_size: '50MB',
        max_objects: 10,
      },
    },
    {
      id: 'unlimited-rule',
      effect: 'ALLOW',
      agent: 'storage-agent',
      action: 'list',
      resource: 'storage/list/**',
    },
  ],
});

describe('Milestone P2.3.1: Capability Bounds Measurement Enforcement (Fail-Closed)', () => {
  const guard = {
    policy: MEASUREMENTS_POLICY,
    evaluate: (req, ctx) => evaluatePolicy(MEASUREMENTS_POLICY, req, ctx),
  };
  const executionGuard = createExecutionGuard({ guard, signingKey: SIGNING_KEY });

  it('rejects maxBytes capability when requestedBytes is missing (BYTE_MEASUREMENT_REQUIRED)', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'STORED' };
    }

    const issuedReq = { action: 'store', resource: 'storage/bytes/data.bin', size: '10MB' };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    // In direct verifyCapability: omitting size measurement
    const verifyResult = verifyCapability(
      capability,
      MEASUREMENTS_POLICY,
      { action: 'store', resource: 'storage/bytes/data.bin' }, // NO size!
      context,
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verifyResult.valid, false);
    assert.equal(verifyResult.code, 'BYTE_MEASUREMENT_REQUIRED');
    assert.match(verifyResult.error, /Capability lease bounds byte limit/);

    // In execution boundary: omitting size measurement
    const protectedStore = executionGuard.protect('store', mockExecutor);
    await assert.rejects(
      async () => {
        await protectedStore(
          { path: 'storage/bytes/data.bin' }, // NO size param!
          { capability, request: { action: 'store', resource: 'storage/bytes/data.bin' }, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'BYTE_MEASUREMENT_REQUIRED');
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('succeeds for maxBytes capability when valid measurement is within limit', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'STORED' };
    }

    const issuedReq = { action: 'store', resource: 'storage/bytes/data.bin', size: '10MB' };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const protectedStore = executionGuard.protect('store', mockExecutor);
    const res = await protectedStore(
      { path: 'storage/bytes/data.bin', size: '10MB' },
      { capability, request: issuedReq, context }
    );

    assert.equal(res.status, 'STORED');
    assert.equal(executorInvoked, true);
  });

  it('rejects maxBytes capability when measurement exceeds limit (BYTE_LIMIT_EXCEEDED)', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'STORED' };
    }

    const issuedReq = { action: 'store', resource: 'storage/bytes/data.bin', size: '10MB' };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const protectedStore = executionGuard.protect('store', mockExecutor);
    await assert.rejects(
      async () => {
        await protectedStore(
          { path: 'storage/bytes/data.bin', size: '100MB' }, // Exceeds 50MB!
          { capability, request: { action: 'store', resource: 'storage/bytes/data.bin', size: '100MB' }, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'BYTE_LIMIT_EXCEEDED');
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('rejects maxObjects capability when requestedCount is missing (OBJECT_MEASUREMENT_REQUIRED)', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'BATCHED' };
    }

    const issuedReq = { action: 'batch', resource: 'storage/objects/batch1', count: 5 };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const verifyResult = verifyCapability(
      capability,
      MEASUREMENTS_POLICY,
      { action: 'batch', resource: 'storage/objects/batch1' }, // NO count!
      context,
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verifyResult.valid, false);
    assert.equal(verifyResult.code, 'OBJECT_MEASUREMENT_REQUIRED');
    assert.match(verifyResult.error, /Capability lease bounds object count limit/);

    const protectedBatch = executionGuard.protect('batch', mockExecutor);
    await assert.rejects(
      async () => {
        await protectedBatch(
          { path: 'storage/objects/batch1' },
          { capability, request: { action: 'batch', resource: 'storage/objects/batch1' }, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'OBJECT_MEASUREMENT_REQUIRED');
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('succeeds for maxObjects capability when valid count is within limit', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'BATCHED' };
    }

    const issuedReq = { action: 'batch', resource: 'storage/objects/batch1', count: 5 };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const protectedBatch = executionGuard.protect('batch', mockExecutor);
    const res = await protectedBatch(
      { path: 'storage/objects/batch1', count: 5 },
      { capability, request: issuedReq, context }
    );

    assert.equal(res.status, 'BATCHED');
    assert.equal(executorInvoked, true);
  });

  it('rejects maxObjects capability when count exceeds limit (OBJECT_LIMIT_EXCEEDED)', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'BATCHED' };
    }

    const issuedReq = { action: 'batch', resource: 'storage/objects/batch1', count: 5 };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const protectedBatch = executionGuard.protect('batch', mockExecutor);
    await assert.rejects(
      async () => {
        await protectedBatch(
          { path: 'storage/objects/batch1', count: 20 }, // Exceeds 10!
          { capability, request: { action: 'batch', resource: 'storage/objects/batch1', count: 20 }, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'OBJECT_LIMIT_EXCEEDED');
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('rejects capability with both limits when both measurements are missing', () => {
    const issuedReq = { action: 'transfer', resource: 'storage/both/bundle', size: '10MB', count: 5 };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const verifyResult = verifyCapability(
      capability,
      MEASUREMENTS_POLICY,
      { action: 'transfer', resource: 'storage/both/bundle' }, // Missing both!
      context,
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verifyResult.valid, false);
    assert.equal(verifyResult.code, 'BYTE_MEASUREMENT_REQUIRED');
  });

  it('rejects capability with both limits when byte size is present but object count is missing', () => {
    const issuedReq = { action: 'transfer', resource: 'storage/both/bundle', size: '10MB', count: 5 };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    const verifyResult = verifyCapability(
      capability,
      MEASUREMENTS_POLICY,
      { action: 'transfer', resource: 'storage/both/bundle', size: '10MB' }, // Count missing!
      context,
      { signingKey: SIGNING_KEY }
    );

    assert.equal(verifyResult.valid, false);
    assert.equal(verifyResult.code, 'OBJECT_MEASUREMENT_REQUIRED');
  });

  it('permits request without measurements when capability has no corresponding limits (null)', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'LISTED' };
    }

    const issuedReq = { action: 'list', resource: 'storage/list/all' };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    // No limits in capability, so omitting size and count is valid
    const verifyResult = verifyCapability(
      capability,
      MEASUREMENTS_POLICY,
      issuedReq,
      context,
      { signingKey: SIGNING_KEY }
    );
    assert.equal(verifyResult.valid, true);

    const protectedList = executionGuard.protect('list', mockExecutor);
    const res = await protectedList(
      { path: 'storage/list/all' },
      { capability, request: issuedReq, context }
    );

    assert.equal(res.status, 'LISTED');
    assert.equal(executorInvoked, true);
  });

  it('treats 0 as a valid measurement and not as missing', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'TRANSFERRED' };
    }

    const issuedReq = { action: 'transfer', resource: 'storage/both/bundle', size: '0B', count: 0 };
    const context = { agentId: 'storage-agent' };
    const decision = guard.evaluate(issuedReq, context);
    const capability = issueCapability({ decision, request: issuedReq, context, options: { signingKey: SIGNING_KEY } });

    // size = 0, count = 0
    const verifyResult = verifyCapability(
      capability,
      MEASUREMENTS_POLICY,
      { action: 'transfer', resource: 'storage/both/bundle', size: 0, count: 0 },
      context,
      { signingKey: SIGNING_KEY }
    );
    assert.equal(verifyResult.valid, true);

    const protectedTransfer = executionGuard.protect('transfer', mockExecutor);
    const res = await protectedTransfer(
      { path: 'storage/both/bundle', size: 0, count: 0 },
      { capability, request: { action: 'transfer', resource: 'storage/both/bundle', size: 0, count: 0 }, context }
    );

    assert.equal(res.status, 'TRANSFERRED');
    assert.equal(executorInvoked, true);
  });
});

const CONSTRAIN_POLICY = compilePolicy({
  name: 'constrain-boolean-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'snapshot-constrained',
      effect: 'ALLOW',
      agent: 'backup-agent',
      action: 'prune',
      resource: 'prod/volumes/**',
      constraints: {
        require_snapshot: true,
      },
    },
    {
      id: 'dry-run-constrained',
      effect: 'ALLOW',
      agent: 'backup-agent',
      action: 'simulate',
      resource: 'prod/sim/**',
      constraints: {
        dry_run_only: true,
      },
    },
  ],
});

describe('Milestone P2.3.1: Strict Boolean Signal Validation in execute()', () => {
  const guard = {
    policy: CONSTRAIN_POLICY,
    evaluate: (req, ctx) => evaluatePolicy(CONSTRAIN_POLICY, req, ctx),
  };
  const executionGuard = createExecutionGuard({ guard, signingKey: SIGNING_KEY });

  it('rejects string "false" for snapshot with TypeError without executing tool', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
    }

    await assert.rejects(
      async () => {
        await executionGuard.execute(
          {
            action: 'prune',
            resource: 'prod/volumes/vol-1',
            snapshot: 'false',
          },
          { agentId: 'backup-agent' },
          mockExecutor
        );
      },
      err => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /Field "snapshot" must be a boolean/);
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('rejects string "true" for snapshot with TypeError without executing tool', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
    }

    await assert.rejects(
      async () => {
        await executionGuard.execute(
          {
            action: 'prune',
            resource: 'prod/volumes/vol-1',
            hasSnapshot: 'true',
          },
          { agentId: 'backup-agent' },
          mockExecutor
        );
      },
      err => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /Field "hasSnapshot" must be a boolean/);
        return true;
      }
    );

    assert.equal(executorInvoked, false);
  });

  it('rejects number 0 and 1 for snapshot with TypeError without executing tool', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
    }

    await assert.rejects(
      async () => {
        await executionGuard.execute(
          {
            action: 'prune',
            resource: 'prod/volumes/vol-1',
            snapshot: 0,
          },
          { agentId: 'backup-agent' },
          mockExecutor
        );
      },
      TypeError
    );

    await assert.rejects(
      async () => {
        await executionGuard.execute(
          {
            action: 'prune',
            resource: 'prod/volumes/vol-1',
            snapshot: 1,
          },
          { agentId: 'backup-agent' },
          mockExecutor
        );
      },
      TypeError
    );

    assert.equal(executorInvoked, false);
  });

  it('rejects non-boolean signals for dryRun (strings "true", "false", numbers 0, 1) with TypeError', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
    }

    await assert.rejects(
      async () => {
        await executionGuard.execute(
          {
            action: 'simulate',
            resource: 'prod/sim/test',
            dryRun: 'true',
          },
          { agentId: 'backup-agent' },
          mockExecutor
        );
      },
      TypeError
    );

    await assert.rejects(
      async () => {
        await executionGuard.execute(
          {
            action: 'simulate',
            resource: 'prod/sim/test',
            isDryRun: 1,
          },
          { agentId: 'backup-agent' },
          mockExecutor
        );
      },
      TypeError
    );

    assert.equal(executorInvoked, false);
  });

  it('preserves valid boolean false and blocks execution as CONSTRAIN prerequisite unfulfilled', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
    }

    const res = await executionGuard.execute(
      {
        action: 'prune',
        resource: 'prod/volumes/vol-1',
        snapshot: false,
      },
      { agentId: 'backup-agent' },
      mockExecutor
    );

    assert.equal(res.executed, false);
    assert.equal(res.constrained, true);
    assert.equal(res.decision.outcome, DecisionOutcome.CONSTRAIN);
    assert.match(res.error, /requires transformation step/);
    assert.equal(executorInvoked, false);
  });

  it('preserves valid boolean true and allows execution', async () => {
    let executorInvoked = false;
    async function mockExecutor() {
      executorInvoked = true;
      return { status: 'PRUNED' };
    }

    const res = await executionGuard.execute(
      {
        action: 'prune',
        resource: 'prod/volumes/vol-1',
        snapshot: true,
      },
      { agentId: 'backup-agent' },
      mockExecutor
    );

    assert.equal(res.executed, true);
    assert.equal(res.result.status, 'PRUNED');
    assert.equal(executorInvoked, true);
  });
});
