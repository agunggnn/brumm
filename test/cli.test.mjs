/**
 * @file test/cli.test.mjs
 * End-to-end tests for the Brumm CLI simulator.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const BIN_PATH = resolve(process.cwd(), 'bin/brumm.mjs');
const POLICY_PATH = resolve(process.cwd(), 'brumm-policy.yaml');

describe('Brumm CLI Simulator', () => {
  it('prints version information', () => {
    const stdout = execFileSync('node', [BIN_PATH, '--version'], { encoding: 'utf8' });
    assert.match(stdout, /brumm v0\.1\.0/);
  });

  it('prints help menu when invoked without arguments', () => {
    const stdout = execFileSync('node', [BIN_PATH, '--help'], { encoding: 'utf8' });
    assert.match(stdout, /The Denial Smart Boss for AI Agents/);
    assert.match(stdout, /brumm policy test/);
  });

  it('returns ALLOW (exit 0) for safe read request', () => {
    const stdout = execFileSync(
      'node',
      [
        BIN_PATH,
        'policy',
        'test',
        '--policy',
        POLICY_PATH,
        '--agent',
        'test-agent',
        '--action',
        'read',
        '--resource',
        '/data/readme.txt',
        '--env',
        'production',
      ],
      { encoding: 'utf8' }
    );

    assert.match(stdout, /Decision:\s+ALLOW/);
    assert.match(stdout, /Policy:\s+production-safeguards/);
  });

  it('supports evaluate subcommand alias and bundled default policy from any working directory', () => {
    const stdout = execFileSync(
      'node',
      [
        BIN_PATH,
        'evaluate',
        '--agent',
        'test-agent',
        '--user',
        'operator',
        '--action',
        'read',
        '--resource',
        '/data/readme.txt',
        '--env',
        'production',
        '--json',
      ],
      { cwd: tmpdir(), encoding: 'utf8' }
    );

    const parsed = JSON.parse(stdout);
    assert.equal(parsed.outcome, 'ALLOW');
    assert.equal(parsed.allowed, true);
  });

  it('returns exit 1 when an explicitly specified --policy file does not exist', () => {
    assert.throws(
      () => {
        execFileSync(
          'node',
          [
            BIN_PATH,
            'policy',
            'test',
            '--policy',
            './non-existent-policy.yaml',
            '--action',
            'read',
            '--resource',
            '/data/readme.txt',
          ],
          { encoding: 'utf8' }
        );
      },
      err => {
        assert.equal(err.status, 1);
        assert.match(err.stderr, /Policy file not found/);
        return true;
      }
    );
  });

  it('returns ESCALATE (exit 2) for honest mistake 700GB deletion', () => {
    assert.throws(
      () => {
        execFileSync(
          'node',
          [
            BIN_PATH,
            'policy',
            'test',
            '--policy',
            POLICY_PATH,
            '--agent',
            'cleanup-agent',
            '--action',
            'delete',
            '--resource',
            'backup-prod/cluster-archive',
            '--size',
            '700GB',
            '--count',
            '1',
            '--env',
            'production',
          ],
          { encoding: 'utf8' }
        );
      },
      err => {
        // Exit code 2 for ESCALATE
        assert.equal(err.status, 2);
        assert.match(err.stdout, /Decision:\s+ESCALATE/);
        assert.match(err.stdout, /exceeds autonomous approval threshold/);
        return true;
      }
    );
  });

  it('returns DENY (exit 1) for critical root wipe', () => {
    assert.throws(
      () => {
        execFileSync(
          'node',
          [
            BIN_PATH,
            'policy',
            'test',
            '--policy',
            POLICY_PATH,
            '--agent',
            'cleanup-agent',
            '--action',
            'delete',
            '--resource',
            '/data/prod-db',
            '--env',
            'production',
          ],
          { encoding: 'utf8' }
        );
      },
      err => {
        // Exit code 1 for DENY
        assert.equal(err.status, 1);
        assert.match(err.stdout, /Decision:\s+DENY/);
        assert.match(err.stdout, /Root-level wipe of production data storage/);
        return true;
      }
    );
  });
});
