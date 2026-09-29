/**
 * @file test/execution-boundary-contracts-and-fallback.test.mjs
 * Security regression tests for Milestone P2.3.4:
 * Execution Boundary: Explicit Tool Binding Contracts & Conservative Fallback
 *
 * 1. Explicit tool contracts (extractResource, extractBytes, extractCount) as authoritative sources
 * 2. Conservative fallback scanner for filename, nested { input: { path } }, and nested { s3: { Bucket, Key } }
 * 3. Implicit payload measurement (Buffer, Uint8Array, and UTF-8 Unicode byte length vs UTF-16 code units)
 * 4. Array item count measurement and bounds enforcement
 * 5. Fail-closed granularity (PARAMETER_SUBSTITUTION_DETECTED, UNBOUND_EXECUTION_PARAMETER, CONTRACT_EVALUATION_ERROR)
 * 6. Contract deep immutability after protect()
 * 7. Unbound/ambiguous parameter denial when capability is bound to a specific resource
 * 8. Safe execution when capability has no relevant bounds (wildcard / null limits)
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createExecutionGuard } from '../src/adapters/tool-adapter.mjs';
import { issueCapability } from '../src/core/capability.mjs';
import { ExecutionSecurityError } from '../src/core/errors.mjs';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { compilePolicy } from '../src/core/policy-loader.mjs';

const SIGNING_KEY = 'test-signing-key-for-p2-3-4-contract-tests!';

const TEST_POLICY = compilePolicy({
  name: 'contract-and-fallback-policy',
  version: '1.0',
  defaultEffect: 'DENY',
  rules: [
    {
      id: 'rule-write',
      effect: 'ALLOW',
      agent: 'worker-agent',
      action: 'write',
      resource: 'data/**',
      constraints: {
        absolute_max_size: '10MB',
        max_objects: 5,
      },
    },
    {
      id: 'rule-upload',
      effect: 'ALLOW',
      agent: 'worker-agent',
      action: 'upload',
      resource: 's3://production-bucket/**',
      constraints: {
        absolute_max_size: '50MB',
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

describe('Milestone P2.3.4: Explicit Tool Binding Contracts (Authoritative)', () => {
  it('enforces explicit extractResource: verifies authorized resource and blocks substitution', async () => {
    const request = { action: 'write', resource: 'data/documents/report.pdf', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let executed = false;
    const protectedWrite = executionGuard.protect(
      'write',
      async (params) => {
        executed = true;
        return { written: true, file: params.docFile };
      },
      {
        contract: {
          extractResource: (params) => params.docFile,
        },
      }
    );

    // Matching resource succeeds
    const res = await protectedWrite(
      { docFile: 'data/documents/report.pdf' },
      { capability, request, context }
    );
    assert.equal(res.written, true);
    assert.equal(executed, true);

    // Substituted resource rejected with PARAMETER_SUBSTITUTION_DETECTED
    const cap2 = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });
    await assert.rejects(
      async () => {
        await protectedWrite(
          { docFile: 'data/sensitive/keys.pem' },
          { capability: cap2, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /Parameter substitution attack detected/);
        return true;
      }
    );
  });

  it('enforces explicit extractBytes: blocks execution when extracted bytes exceed capability limit', async () => {
    const request = { action: 'write', resource: 'data/file.bin', size: '5MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect(
      'write',
      async () => ({ written: true }),
      {
        contract: {
          extractResource: (params) => params.file,
          extractBytes: (params) => params.rawBlob?.length,
        },
      }
    );

    // 15MB blob exceeds capability lease limit (10MB)
    const largeBlob = Buffer.alloc(15 * 1024 * 1024);
    await assert.rejects(
      async () => {
        await protectedWrite(
          { file: 'data/file.bin', rawBlob: largeBlob },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'BYTE_LIMIT_EXCEEDED');
        return true;
      }
    );
  });

  it('enforces explicit extractCount: blocks execution when extracted count exceeds capability limit', async () => {
    const request = { action: 'write', resource: 'data/batch', size: '1MB', count: 3 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect(
      'write',
      async () => ({ batch: true }),
      {
        contract: {
          extractResource: (params) => params.path,
          extractCount: (params) => params.entries?.length,
        },
      }
    );

    // 10 entries exceeds capability limit (5 objects)
    await assert.rejects(
      async () => {
        await protectedWrite(
          { path: 'data/batch', entries: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'OBJECT_LIMIT_EXCEEDED');
        return true;
      }
    );
  });

  it('fails closed when contract extractor returns undefined for a required bound (UNBOUND_EXECUTION_PARAMETER)', async () => {
    const request = { action: 'write', resource: 'data/target.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect(
      'write',
      async () => ({ written: true }),
      {
        contract: {
          // Extractor returns undefined
          extractResource: () => undefined,
        },
      }
    );

    await assert.rejects(
      async () => {
        await protectedWrite(
          { target: 'data/target.txt' },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNBOUND_EXECUTION_PARAMETER');
        assert.match(err.message, /failed to resolve required resource/);
        return true;
      }
    );
  });

  it('fails closed when contract extractor throws an error (CONTRACT_EVALUATION_ERROR)', async () => {
    const request = { action: 'write', resource: 'data/target.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect(
      'write',
      async () => ({ written: true }),
      {
        contract: {
          extractResource: () => {
            throw new Error('Database connection failed during resource resolution');
          },
        },
      }
    );

    await assert.rejects(
      async () => {
        await protectedWrite(
          { target: 'data/target.txt' },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'CONTRACT_EVALUATION_ERROR');
        assert.match(err.message, /contract\.extractResource threw an error/);
        return true;
      }
    );
  });

  it('freezes contract deeply upon protect() to prevent post-creation tampering', () => {
    const mutableContract = {
      extractResource: (p) => p.file,
      metadata: { author: 'trusted' },
    };

    executionGuard.protect('write', async () => {}, { contract: mutableContract });

    // Attempting to mutate original contract or its properties throws TypeError
    assert.throws(() => {
      mutableContract.extractResource = () => 'tampered';
    }, TypeError);

    assert.throws(() => {
      mutableContract.metadata.author = 'malicious';
    }, TypeError);
  });
});

describe('Milestone P2.3.4: Conservative Fallback Scanner (Advisory / Defense-in-Depth)', () => {
  it('detects and binds "filename" parameter not present in legacy candidate list', async () => {
    const request = { action: 'write', resource: 'data/report.csv', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect('write', async () => ({ status: 'OK' }));

    // Valid filename matching authorized resource
    const res = await protectedWrite(
      { filename: 'data/report.csv' },
      { capability, request, context }
    );
    assert.equal(res.status, 'OK');

    // Filename pointing to unauthorized target blocked
    const cap2 = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });
    await assert.rejects(
      async () => {
        await protectedWrite(
          { filename: 'data/evil.csv' },
          { capability: cap2, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "filename"/);
        return true;
      }
    );
  });

  it('detects nested parameter structures: { input: { path } }', async () => {
    const request = { action: 'write', resource: 'data/logs/app.log', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect('write', async () => ({ status: 'OK' }));

    // Valid nested input.path
    const res = await protectedWrite(
      { input: { path: 'data/logs/app.log' } },
      { capability, request, context }
    );
    assert.equal(res.status, 'OK');

    // Unauthorized nested input.path blocked
    const cap2 = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });
    await assert.rejects(
      async () => {
        await protectedWrite(
          { input: { path: '/etc/shadow' } },
          { capability: cap2, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "input\.path"/);
        return true;
      }
    );
  });

  it('detects nested S3 structure: { s3: { Bucket, Key } }', async () => {
    const request = { action: 'upload', resource: 's3://production-bucket/backups/daily.tar.gz', size: '10MB' };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedUpload = executionGuard.protect('upload', async () => ({ uploaded: true }));

    // Valid nested s3 object
    const res = await protectedUpload(
      { s3: { Bucket: 'production-bucket', Key: 'backups/daily.tar.gz' } },
      { capability, request, context }
    );
    assert.equal(res.uploaded, true);

    // Mismatched bucket in nested S3
    const cap2 = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });
    await assert.rejects(
      async () => {
        await protectedUpload(
          { s3: { Bucket: 'malicious-bucket', Key: 'backups/daily.tar.gz' } },
          { capability: cap2, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "s3\.bucket\/key"/);
        return true;
      }
    );
  });

  it('blocks nested malicious parameter attempting to smuggle an unauthorized target alongside valid target', async () => {
    const request = { action: 'write', resource: 'data/valid.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect('write', async () => ({ status: 'OK' }));

    // Attacker supplies valid path at top level, but smuggles malicious target in input.filename
    await assert.rejects(
      async () => {
        await protectedWrite(
          {
            path: 'data/valid.txt',
            input: { filename: '/var/secret/private.key' },
          },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'PARAMETER_SUBSTITUTION_DETECTED');
        assert.match(err.message, /parameter "input\.filename"/);
        return true;
      }
    );
  });

  it('fails closed when capability is bound to a specific resource but parameters contain unrecognized keys and no contract', async () => {
    const request = { action: 'write', resource: 'data/file.txt', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect('write', async () => ({ status: 'OK' }));

    // Attacker supplies an unrecognized target parameter key to bypass scanner
    await assert.rejects(
      async () => {
        await protectedWrite(
          { unknownTargetParam: '/etc/passwd' },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNBOUND_EXECUTION_PARAMETER');
        assert.match(err.message, /do not expose a recognizable resource binding and no tool contract was provided/);
        return true;
      }
    );
  });
});

describe('Milestone P2.3.4: Implicit Payload Measurements (Buffers & Unicode UTF-8 Bytes)', () => {
  it('blocks execution when Buffer body exceeds capability maxBytes (10MB)', async () => {
    const request = { action: 'write', resource: 'data/blob.bin', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect('write', async () => ({ status: 'OK' }));

    // 12MB Buffer payload exceeds 10MB limit
    const buffer12MB = Buffer.alloc(12 * 1024 * 1024);
    await assert.rejects(
      async () => {
        await protectedWrite(
          { path: 'data/blob.bin', body: buffer12MB },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'BYTE_LIMIT_EXCEEDED');
        assert.match(err.message, /exceeds (authorized request size|capability lease limit)/);
        return true;
      }
    );
  });

  it('strictly computes UTF-8 byte length for Unicode strings instead of UTF-16 code units (.length)', async () => {
    // Policy rule allows max 30 bytes for writing to 'data/unicode/**'
    const unicodePolicy = compilePolicy({
      name: 'unicode-test-policy',
      version: '1.0',
      defaultEffect: 'DENY',
      rules: [
        {
          id: 'unicode-rule',
          effect: 'ALLOW',
          agent: 'worker-agent',
          action: 'write',
          resource: 'data/unicode/**',
          constraints: {
            absolute_max_size: 30, // Max 30 bytes!
          },
        },
      ],
    });

    const uniGuard = {
      policy: unicodePolicy,
      evaluate: (req, ctx) => evaluatePolicy(unicodePolicy, req, ctx),
    };
    const uniExecGuard = createExecutionGuard({ guard: uniGuard, signingKey: SIGNING_KEY });

    const request = { action: 'write', resource: 'data/unicode/test.txt', size: 10 };
    const context = { agentId: 'worker-agent' };
    const decision = uniGuard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = uniExecGuard.protect('write', async () => ({ status: 'OK' }));

    // String with 10 rocket emojis:
    // In UTF-16 JavaScript string: rocket.length is 2. 10 * 2 = 20 UTF-16 code units.
    // In UTF-8 bytes: each rocket is 4 bytes (F0 9F 9A 80). 10 * 4 = 40 UTF-8 bytes!
    // 20 code units would dangerously bypass 30 bytes limit if string.length were used.
    // Buffer.byteLength detects 40 bytes > 30 bytes limit and blocks it!
    const unicodeStr = '🚀'.repeat(10);
    assert.equal(unicodeStr.length, 20); // UTF-16 code units: 20
    assert.equal(Buffer.byteLength(unicodeStr, 'utf8'), 40); // UTF-8 byte length: 40

    await assert.rejects(
      async () => {
        await protectedWrite(
          { path: 'data/unicode/test.txt', content: unicodeStr },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'BYTE_LIMIT_EXCEEDED');
        assert.match(err.message, /40B/);
        return true;
      }
    );
  });

  it('detects array item counts in "items" parameter and enforces maxObjects constraint', async () => {
    const request = { action: 'write', resource: 'data/batch.json', size: '1MB', count: 2 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    const protectedWrite = executionGuard.protect('write', async () => ({ status: 'OK' }));

    // Array with 8 items exceeds max_objects: 5
    await assert.rejects(
      async () => {
        await protectedWrite(
          { path: 'data/batch.json', items: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'OBJECT_LIMIT_EXCEEDED');
        assert.match(err.message, /8/);
        return true;
      }
    );
  });
});

describe('Milestone P2.3.4: Capabilities Without Relevant Bounds & Wildcard Resources', () => {
  it('allows execution when capability has wildcard resource ("*") and no size/count limits', async () => {
    const request = { action: 'ping', resource: '*' };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let pingInvoked = false;
    const protectedPing = executionGuard.protect('ping', async () => {
      pingInvoked = true;
      return { pong: true };
    });

    const res = await protectedPing(
      { anyArbitraryParameter: 'arbitraryValue', timestamp: Date.now() },
      { capability, request, context }
    );

    assert.equal(res.pong, true);
    assert.equal(pingInvoked, true);
  });
});

describe('Milestone P2.3.5: Execution Boundary TOCTOU Defense & Bounded Quota Preflight', () => {
  it('blocks getter changing value between reads (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'write', resource: 'data/report.pdf', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecuted = false;
    const protectedWrite = executionGuard.protect('write', async () => {
      rawExecuted = true;
    });

    let reads = 0;
    const getterParams = {
      get path() {
        reads++;
        return reads === 1 ? 'data/report.pdf' : '/etc/shadow';
      },
    };

    await assert.rejects(
      async () => {
        await protectedWrite(getterParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        return true;
      }
    );

    assert.equal(rawExecuted, false);
  });

  it('blocks Proxy parameter trapping property access (UNTRUSTED_PARAMETER_ACCESSOR)', async () => {
    const request = { action: 'write', resource: 'data/report.pdf', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecuted = false;
    const protectedWrite = executionGuard.protect('write', async () => {
      rawExecuted = true;
    });

    let trapCalls = 0;
    const proxyParams = new Proxy({ path: 'data/report.pdf' }, {
      get(target, prop, receiver) {
        trapCalls++;
        if (prop === 'path') {
          return trapCalls === 1 ? 'data/report.pdf' : '/etc/shadow';
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    await assert.rejects(
      async () => {
        await protectedWrite(proxyParams, { capability, request, context });
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'UNTRUSTED_PARAMETER_ACCESSOR');
        return true;
      }
    );

    assert.equal(rawExecuted, false);
  });

  it('insulates execution from caller mutation of nested object after protect call', async () => {
    const request = { action: 'write', resource: 'data/report.pdf', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedWrite = executionGuard.protect('write', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const callerParams = {
      path: 'data/report.pdf',
      input: {
        target: 'data/report.pdf',
      },
    };

    const callPromise = protectedWrite(callerParams, { capability, request, context });

    // Mutate caller's nested object immediately
    callerParams.input.target = '/etc/shadow';
    callerParams.path = '/etc/shadow';

    const res = await callPromise;
    assert.equal(res.success, true);
    assert.ok(capturedParams);
    assert.equal(capturedParams.path, 'data/report.pdf');
    assert.equal(capturedParams.input.target, 'data/report.pdf');
    assert.equal(Object.isFrozen(capturedParams.input), true);
  });

  it('insulates execution from caller mutation of array after protect call', async () => {
    const request = { action: 'write', resource: 'data/batch', size: '1MB', count: 2 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedWrite = executionGuard.protect('write', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const callerItems = ['item1', 'item2'];
    const callerParams = {
      path: 'data/batch',
      items: callerItems,
    };

    const callPromise = protectedWrite(callerParams, { capability, request, context });

    // Mutate caller's array
    callerItems.push('item3', 'item4');

    const res = await callPromise;
    assert.equal(res.success, true);
    assert.equal(capturedParams.items.length, 2);
    assert.deepEqual(capturedParams.items, ['item1', 'item2']);
    assert.equal(Object.isFrozen(capturedParams.items), true);
  });

  it('insulates execution from caller in-place mutation of Buffer payload after snapshot', async () => {
    const request = { action: 'write', resource: 'data/blob.bin', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedWrite = executionGuard.protect('write', async (params) => {
      capturedParams = params;
      return { success: true };
    });

    const originalBuffer = Buffer.from('unmodified content');
    const callerParams = {
      path: 'data/blob.bin',
      body: originalBuffer,
    };

    const callPromise = protectedWrite(callerParams, { capability, request, context });

    // Mutate buffer memory in-place
    originalBuffer[0] = 0x5a; // 'Z'

    const res = await callPromise;
    assert.equal(res.success, true);
    assert.equal(capturedParams.body.toString('utf8'), 'unmodified content');
    assert.notEqual(capturedParams.body, originalBuffer);
  });

  it('guarantees rawExecutor receives detached deeply frozen snapshot', async () => {
    const request = { action: 'write', resource: 'data/report.pdf', size: '1MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let capturedParams = null;
    const protectedWrite = executionGuard.protect('write', async (params) => {
      capturedParams = params;
      return { ok: true };
    });

    await protectedWrite(
      { path: 'data/report.pdf', meta: { tag: 'pdf-doc' } },
      { capability, request, context }
    );

    assert.equal(Object.isFrozen(capturedParams), true);
    assert.equal(Object.isFrozen(capturedParams.meta), true);
    assert.equal(capturedParams._authorizedResource, 'data/report.pdf');
    assert.equal(capturedParams._authorizedAction, 'write');
  });

  it('bounded preflight rejects oversized Buffer before cloning/allocating memory', async () => {
    // 20MB buffer exceeds 10MB capability maxBytes and 5MB request size
    const request = { action: 'write', resource: 'data/large.bin', size: '5MB', count: 1 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecuted = false;
    const protectedWrite = executionGuard.protect('write', async () => {
      rawExecuted = true;
    });

    const oversizedBuffer = Buffer.alloc(20 * 1024 * 1024);

    await assert.rejects(
      async () => {
        await protectedWrite(
          { path: 'data/large.bin', body: oversizedBuffer },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'BYTE_LIMIT_EXCEEDED');
        assert.match(err.message, /exceeds (authorized request size|capability lease limit)/);
        return true;
      }
    );

    assert.equal(rawExecuted, false);
  });

  it('bounded preflight rejects oversized array before cloning/allocating memory', async () => {
    // 15 items exceeds max_objects: 5
    const request = { action: 'write', resource: 'data/batch', size: '1MB', count: 2 };
    const context = { agentId: 'worker-agent' };
    const decision = guard.evaluate(request, context);
    const capability = issueCapability({ decision, request, context, options: { signingKey: SIGNING_KEY } });

    let rawExecuted = false;
    const protectedWrite = executionGuard.protect('write', async () => {
      rawExecuted = true;
    });

    const oversizedArray = new Array(15).fill('item');

    await assert.rejects(
      async () => {
        await protectedWrite(
          { path: 'data/batch', items: oversizedArray },
          { capability, request, context }
        );
      },
      err => {
        assert.ok(err instanceof ExecutionSecurityError);
        assert.equal(err.code, 'OBJECT_LIMIT_EXCEEDED');
        assert.match(err.message, /exceeds (authorized request count|capability lease limit)/);
        return true;
      }
    );

    assert.equal(rawExecuted, false);
  });
});
