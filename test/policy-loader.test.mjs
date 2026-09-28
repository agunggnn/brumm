/**
 * @file test/policy-loader.test.mjs
 * Unit tests for YAML/JSON policy parsing and deterministic hashing.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  compilePolicy,
  computePolicyHash,
  parseYamlSubset,
} from '../src/core/policy-loader.mjs';

describe('YAML Subset Parser', () => {
  it('parses standard YAML mappings and scalar types', () => {
    const yaml = `
name: test-policy
version: "1.0"
active: true
count: 42
threshold: 50.5
`;
    const res = parseYamlSubset(yaml);
    assert.equal(res.name, 'test-policy');
    assert.equal(res.version, '1.0');
    assert.equal(res.active, true);
    assert.equal(res.count, 42);
    assert.equal(res.threshold, 50.5);
  });

  it('parses YAML sequences of objects', () => {
    const yaml = `
rules:
  - id: rule-1
    action: delete
    effect: DENY
  - id: rule-2
    action: read
    effect: ALLOW
`;
    const res = parseYamlSubset(yaml);
    assert.equal(res.rules.length, 2);
    assert.equal(res.rules[0].id, 'rule-1');
    assert.equal(res.rules[0].effect, 'DENY');
    assert.equal(res.rules[1].action, 'read');
  });

  it('computes deterministic SHA-256 policy hash', () => {
    const policyA = { name: 'pol', version: '1.0', rules: [] };
    const policyB = { version: '1.0', name: 'pol', rules: [] };

    const hashA = computePolicyHash(policyA);
    const hashB = computePolicyHash(policyB);

    assert.equal(hashA, hashB);
    assert.equal(typeof hashA, 'string');
    assert.equal(hashA.length, 64);
  });

  it('compiles policy rules and parses size strings', () => {
    const raw = {
      name: 'cleanup',
      rules: [
        {
          id: 'rule-del',
          effect: 'ALLOW',
          constraints: {
            max_size: '50GB',
            require_snapshot: true,
          },
        },
      ],
    };

    const compiled = compilePolicy(raw);
    assert.equal(compiled.rules.length, 1);
    assert.equal(compiled.rules[0].constraints.maxBytes, 50 * 1024 * 1024 * 1024);
    assert.equal(compiled.rules[0].constraints.requireSnapshot, true);
  });
});
