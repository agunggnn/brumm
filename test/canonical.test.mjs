/**
 * @file test/canonical.test.mjs
 * Unit tests for resource canonicalization and traversal defense.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { canonicalizeResource, matchResourcePattern } from '../src/core/canonical.mjs';

describe('Canonical Resource Normalization', () => {
  it('normalizes backslashes to forward slashes', () => {
    const res = canonicalizeResource('backup-prod\\data\\file.txt');
    assert.equal(res.uri, 'backup-prod/data/file.txt');
    assert.equal(res.path, 'backup-prod/data/file.txt');
  });

  it('resolves relative "." and ".." dot segments', () => {
    const res = canonicalizeResource('/var/data/prod/../archive/./test.log');
    assert.equal(res.uri, '/var/data/archive/test.log');
  });

  it('rejects path traversal attempting to escape root', () => {
    assert.throws(
      () => canonicalizeResource('/var/../../etc/passwd'),
      /Path traversal detected/
    );
  });

  it('rejects null byte injection attacks', () => {
    assert.throws(
      () => canonicalizeResource('backup-prod/file.txt\0.admin'),
      /null byte/
    );
  });

  it('preserves URI schemes (s3, file, k8s)', () => {
    const s3 = canonicalizeResource('s3://my-prod-bucket/backups/../snapshots/2024');
    assert.equal(s3.uri, 's3://my-prod-bucket/snapshots/2024');
    assert.equal(s3.scheme, 's3');
  });

  it('enforces base directory constraint if specified', () => {
    assert.throws(
      () => canonicalizeResource('/var/log/app.log', { baseDir: '/var/data' }),
      /Resource substitution detected/
    );
  });
});

describe('Resource Pattern Matching', () => {
  it('matches wildcards within segment (*)', () => {
    assert.equal(matchResourcePattern('/data/prod.db', '/data/*.db'), true);
    assert.equal(matchResourcePattern('/data/staging.db', '/data/*.db'), true);
    assert.equal(matchResourcePattern('/data/nested/prod.db', '/data/*.db'), false);
  });

  it('matches globstar across multiple segments (**)', () => {
    assert.equal(matchResourcePattern('backup-prod/2024/09/db.tar.gz', 'backup-prod/**'), true);
    assert.equal(matchResourcePattern('other-backup/2024', 'backup-prod/**'), false);
  });
});
