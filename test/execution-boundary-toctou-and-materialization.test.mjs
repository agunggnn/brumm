/**
 * @file test/execution-boundary-toctou-and-materialization.test.mjs
 * Security regression tests for Milestone P2.3.5 / P2.3.4-01:
 * Execution Boundary TOCTOU Defense via Deeply Immutable Materialized Parameter Snapshot
 *
 * 1. Rejects property accessors (getters/setters) to prevent TOCTOU substitution (UNTRUSTED_PARAMETER_ACCESSOR)
 * 2. Rejects Proxy objects to prevent dynamic value trapping (UNTRUSTED_PARAMETER_ACCESSOR)
 * 3. Rejects prototype pollution keys: __proto__, constructor, prototype (PROTOTYPE_POLLUTION_DETECTED)
 * 4. Rejects function values (UNTRUSTED_PARAMETER_FUNCTION) and symbols (UNTRUSTED_PARAMETER_SYMBOL)
 * 5. Rejects circular references (CIRCULAR_PARAMETER_REFERENCE)
 * 6. Supports non-circular DAGs (shared object references) without false positives
 * 7. Rejects excessive nesting depth (PARAMETER_MAX_DEPTH_EXCEEDED)
 * 8. Rejects non-plain objects with custom prototypes (INVALID_PARAMETERS)
 * 9. Immune to caller mutation of nested objects and arrays after protect()
 * 10. Immune to caller in-place mutation of Buffers and Uint8Arrays (detached copies)
 * 11. Guarantees rawExecutor receives the exact same frozen snapshot inspected by verification
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createExecutionGuard,
  materializeExecutionParams,
} from '../src/index.mjs';
import { isDeepFrozen } from '../src/core/canonical-json.mjs';
import { issueCapability } from '../src/core/capability.mjs';
import { ExecutionSecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const SIGNING_KEY = 'test-signing-key-for-toctou-hardening!';

const TEST_POLICY = compilePolicy({
  name: 'toctou-defense-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'rule-file-ops',
      effect: 'ALLOW',
      agent: 'worker-agent',
      action: 'process',
      resource: 'data/**',
      constraints: {
        absolute_max_size: '10MB',
        max_objects: 5,
      },
    },
    {
      id: 'rule-wildcard',
      effect: 'ALLOW',
      agent: 'worker-agent',
      action: 'ping',
      resource: '*',
    },
  ],
});

const guard = {
  policy: TEST_POLICY,
  evaluate: (req, ctx) => evaluatePolicy(TEST_POLICY, req, ctx),
};

const executionGuard = createExecutionGuard({ guard, signingKey: SIGNING_KEY });

describe('Milestone P2.3.5: Execution-Boundary TOCTOU Defense via Materialized Snapshot', () => {
  it('blocks root-level getter changing values between verification and execution (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecutorCalled = false;
    const protectedProcess = executionGuard.protect('process', async () => {
      rawExecutorCalled = true;
      return { status: 'DONE' };
    });

    // Attacker crafts an object with a getter that returns 'data/safe.txt' on read 1 and '/etc/shadow' on read 2
    let reads = 0;
    const maliciousParams = {
      get path() {
        reads++;
        return reads === 1 ? 'data/safe.txt' : '/etc/shadow';
      },
    };

    await assert.rejects(
      async () => {
        await protectedProcess(maliciousParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        assert.match(err.message, /Untrusted parameter accessor detected on property "path"/);
        return true;
      }
    );

    assert.equal(rawExecutorCalled, false);
  });

  it('blocks setter-only property on parameter object (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecutorCalled = false;
    const protectedProcess = executionGuard.protect('process', async () => {
      rawExecutorCalled = true;
    });

    const maliciousParams = {
      path: 'data/safe.txt',
      set trap(v) {},
    };

    await assert.rejects(
      async () => {
        await protectedProcess(maliciousParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        assert.match(err.message, /property "trap"/);
        return true;
      }
    );

    assert.equal(rawExecutorCalled, false);
  });

  it('blocks nested getter property (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecutorCalled = false;
    const protectedProcess = executionGuard.protect('process', async () => {
      rawExecutorCalled = true;
    });

    const maliciousParams = {
      input: {
        get target() {
          return '/etc/shadow';
        },
      },
    };

    await assert.rejects(
      async () => {
        await protectedProcess(maliciousParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        assert.match(err.message, /property "target"/);
        return true;
      }
    );

    assert.equal(rawExecutorCalled, false);
  });

  it('blocks array element accessor (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecutorCalled = false;
    const protectedProcess = executionGuard.protect('process', async () => {
      rawExecutorCalled = true;
    });

    const maliciousArray = ['data/safe.txt'];
    Object.defineProperty(maliciousArray, '0', {
      get() {
        return '/etc/shadow';
      },
      enumerable: true,
      configurable: true,
    });

    await assert.rejects(
      async () => {
        await protectedProcess({ path: 'data/safe.txt', items: maliciousArray }, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        return true;
      }
    );

    assert.equal(rawExecutorCalled, false);
  });

  it('blocks root Proxy parameter object (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecutorCalled = false;
    const protectedProcess = executionGuard.protect('process', async () => {
      rawExecutorCalled = true;
    });

    let getCalls = 0;
    const proxyParams = new Proxy({ path: 'data/safe.txt' }, {
      get(target, prop, receiver) {
        getCalls++;
        if (prop === 'path') {
          return getCalls === 1 ? 'data/safe.txt' : '/etc/shadow';
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    await assert.rejects(
      async () => {
        await protectedProcess(proxyParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        assert.match(err.message, /Untrusted parameter proxy detected/);
        return true;
      }
    );

    assert.equal(rawExecutorCalled, false);
  });

  it('blocks nested Proxy parameter object (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecutorCalled = false;
    const protectedProcess = executionGuard.protect('process', async () => {
      rawExecutorCalled = true;
    });

    const nestedProxyParams = {
      path: 'data/safe.txt',
      input: new Proxy({ target: 'data/safe.txt' }, {}),
    };

    await assert.rejects(
      async () => {
        await protectedProcess(nestedProxyParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        assert.match(err.message, /Untrusted parameter proxy detected/);
        return true;
      }
    );

    assert.equal(rawExecutorCalled, false);
  });

  it('immune to caller mutation of nested objects after protect() invocation', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedProcess = executionGuard.protect('process', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const callerParams = {
      path: 'data/safe.txt',
      input: {
        target: 'data/safe.txt',
        mode: 'read',
      },
    };

    // Invoke protected process
    const resPromise = protectedProcess(callerParams, { capability, request, context });

    // Caller immediately mutates the nested object
    callerParams.input.target = '/etc/shadow';
    callerParams.input.mode = 'destroy';
    callerParams.path = '/etc/shadow';

    const res = await resPromise;
    assert.equal(res.success, true);
    assert.ok(capturedParams);

    // The captured parameter inside rawExecutor was completely insulated from mutation!
    assert.equal(capturedParams.path, 'data/safe.txt');
    assert.equal(capturedParams.input.target, 'data/safe.txt');
    assert.equal(capturedParams.input.mode, 'read');

    // Captured parameters and nested objects are deeply frozen
    assert.equal(Object.isFrozen(capturedParams), true);
    assert.equal(Object.isFrozen(capturedParams.input), true);
    assert.equal(isDeepFrozen(capturedParams), true);

    // Mutation of captured parameters inside or outside rawExecutor throws in strict mode
    assert.throws(() => {
      capturedParams.input.target = 'tampered';
    }, TypeError);
  });

  it('immune to caller mutation of arrays after protect() invocation', async () => {
    const request = { action: 'process', resource: 'data/batch.json', size: '1MB', count: 2 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedProcess = executionGuard.protect('process', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const callerItems = ['item-1', 'item-2'];
    const callerParams = {
      path: 'data/batch.json',
      items: callerItems,
    };

    const resPromise = protectedProcess(callerParams, { capability, request, context });

    // Caller mutates array by pushing malicious elements
    callerItems.push('item-evil-3', 'item-evil-4');

    const res = await resPromise;
    assert.equal(res.success, true);
    assert.ok(capturedParams);

    // Captured array retained original 2 items
    assert.equal(capturedParams.items.length, 2);
    assert.deepEqual(capturedParams.items, ['item-1', 'item-2']);
    assert.equal(Object.isFrozen(capturedParams.items), true);

    assert.throws(() => {
      capturedParams.items.push('tampered');
    }, TypeError);
  });

  it('immune to caller mutation of Buffer payload (detached copy)', async () => {
    const request = { action: 'process', resource: 'data/binary.bin', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedProcess = executionGuard.protect('process', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const rawBuffer = Buffer.from('trusted payload');
    const callerParams = {
      path: 'data/binary.bin',
      body: rawBuffer,
    };

    const resPromise = protectedProcess(callerParams, { capability, request, context });

    // In-place byte modification on original buffer
    rawBuffer[0] = 0x58; // 'X'
    rawBuffer[1] = 0x58;

    const res = await resPromise;
    assert.equal(res.success, true);

    // Captured buffer was cloned and preserved
    assert.equal(capturedParams.body.toString('utf8'), 'trusted payload');
    assert.notEqual(capturedParams.body, rawBuffer);
  });

  it('blocks prototype pollution via __proto__ (PROTOTYPE_POLLUTION_DETECTED)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    const pollutedParams = JSON.parse('{"path": "data/safe.txt", "__proto__": {"admin": true}}');

    await assert.rejects(
      async () => {
        await protectedProcess(pollutedParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PROTOTYPE_POLLUTION_DETECTED');
        assert.match(err.message, /Prototype pollution key "__proto__"/);
        return true;
      }
    );
  });

  it('blocks prototype pollution via constructor (PROTOTYPE_POLLUTION_DETECTED)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    const pollutedParams = {
      path: 'data/safe.txt',
      constructor: { prototype: { admin: true } },
    };

    await assert.rejects(
      async () => {
        await protectedProcess(pollutedParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PROTOTYPE_POLLUTION_DETECTED');
        assert.match(err.message, /Prototype pollution key "constructor"/);
        return true;
      }
    );
  });

  it('blocks prototype pollution via prototype property (PROTOTYPE_POLLUTION_DETECTED)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    const pollutedParams = {
      path: 'data/safe.txt',
      prototype: { evil: true },
    };

    await assert.rejects(
      async () => {
        await protectedProcess(pollutedParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PROTOTYPE_POLLUTION_DETECTED');
        assert.match(err.message, /Prototype pollution key "prototype"/);
        return true;
      }
    );
  });

  it('blocks function values in execution parameters (UNTRUSTED_PARAMETER_FUNCTION)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    await assert.rejects(
      async () => {
        await protectedProcess(
          { path: 'data/safe.txt', callback: () => 'malicious' },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_FUNCTION');
        return true;
      }
    );
  });

  it('blocks symbol keys and symbol values (UNTRUSTED_PARAMETER_SYMBOL)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    // Symbol value
    await assert.rejects(
      async () => {
        await protectedProcess(
          { path: 'data/safe.txt', symVal: Symbol('secret') },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_SYMBOL');
        return true;
      }
    );

    // Symbol key
    const symKey = Symbol('untrustedKey');
    await assert.rejects(
      async () => {
        await protectedProcess(
          { path: 'data/safe.txt', [symKey]: 'untrustedValue' },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_SYMBOL');
        return true;
      }
    );
  });

  it('blocks circular references in parameters (CIRCULAR_PARAMETER_REFERENCE)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    const cyclicParams = { path: 'data/safe.txt' };
    cyclicParams.self = cyclicParams;

    await assert.rejects(
      async () => {
        await protectedProcess(cyclicParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'CIRCULAR_PARAMETER_REFERENCE');
        return true;
      }
    );
  });

  it('allows non-circular DAGs (shared object references across sibling keys)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedProcess = executionGuard.protect('process', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const sharedSubObject = { metadataKey: 'metadataValue' };
    const dagParams = {
      path: 'data/safe.txt',
      primaryMeta: sharedSubObject,
      secondaryMeta: sharedSubObject,
    };

    const res = await protectedProcess(dagParams, { capability, request, context });
    assert.equal(res.success, true);
    assert.equal(capturedParams.primaryMeta.metadataKey, 'metadataValue');
    assert.equal(capturedParams.secondaryMeta.metadataKey, 'metadataValue');
  });

  it('blocks nesting depth exceeding maxDepth (PARAMETER_MAX_DEPTH_EXCEEDED)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    // Create 12 levels of nesting (default maxDepth is 10)
    let deeplyNested = { path: 'data/safe.txt' };
    for (let i = 0; i < 12; i++) {
      deeplyNested = { level: deeplyNested };
    }

    await assert.rejects(
      async () => {
        await protectedProcess(deeplyNested, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_MAX_DEPTH_EXCEEDED');
        assert.match(err.message, /exceed maximum allowed nesting depth/);
        return true;
      }
    );
  });

  it('blocks custom class instances with non-plain prototypes (INVALID_PARAMETERS)', async () => {
    const request = { action: 'process', resource: 'data/safe.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedProcess = executionGuard.protect('process', async () => {});

    class CustomParams {
      constructor() {
        this.path = 'data/safe.txt';
      }
    }

    await assert.rejects(
      async () => {
        await protectedProcess(new CustomParams(), { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'INVALID_PARAMETERS');
        assert.match(err.message, /expected plain object/);
        return true;
      }
    );
  });

  it('direct materializeExecutionParams unit tests: options, defaults, edge cases', () => {
    // null and undefined return frozen empty object
    const nullSnap = materializeExecutionParams(null);
    assert.deepEqual(nullSnap, {});
    assert.equal(Object.isFrozen(nullSnap), true);

    const undefSnap = materializeExecutionParams(undefined);
    assert.deepEqual(undefSnap, {});
    assert.equal(Object.isFrozen(undefSnap), true);

    // Non-object primitives at root throw INVALID_PARAMETERS
    assert.throws(() => materializeExecutionParams(123), err => err.code === 'INVALID_PARAMETERS');
    assert.throws(() => materializeExecutionParams('string'), err => err.code === 'INVALID_PARAMETERS');
    assert.throws(() => materializeExecutionParams(true), err => err.code === 'INVALID_PARAMETERS');
    assert.throws(() => materializeExecutionParams(['array']), err => err.code === 'INVALID_PARAMETERS');

    // Configurable maxDepth option
    let nested3 = { a: { b: { c: { d: 1 } } } };
    assert.throws(
      () => materializeExecutionParams(nested3, 2),
      err => err.code === 'PARAMETER_MAX_DEPTH_EXCEEDED'
    );
    assert.throws(
      () => materializeExecutionParams(nested3, { maxDepth: 2 }),
      err => err.code === 'PARAMETER_MAX_DEPTH_EXCEEDED'
    );
    const okSnap = materializeExecutionParams(nested3, 5);
    assert.equal(okSnap.a.b.c.d, 1);
    assert.equal(isDeepFrozen(okSnap), true);

    // Dates and typed arrays
    const testDate = new Date('2026-09-28T00:00:00Z');
    const testU8 = new Uint8Array([1, 2, 3, 4]);
    const testAB = new ArrayBuffer(8);
    const snapMedia = materializeExecutionParams({ date: testDate, u8: testU8, ab: testAB });

    assert.equal(snapMedia.date.toISOString(), testDate.toISOString());
    assert.notEqual(snapMedia.date, testDate);
    assert.deepEqual(Array.from(snapMedia.u8), [1, 2, 3, 4]);
    assert.notEqual(snapMedia.u8, testU8);
    assert.equal(snapMedia.ab.byteLength, 8);
    assert.notEqual(snapMedia.ab, testAB);
  });
});
