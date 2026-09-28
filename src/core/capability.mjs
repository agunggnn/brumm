/**
 * @file capability.mjs
 * Dynamic Capability Engine (JEV Primitive) for Brumm.
 * Issues ephemeral, audience-bound, cryptographically signed capability leases
 * with single-use nonce replay defense and TOCTOU policy-hash binding.
 */

import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { canonicalizeJson, deepFreeze } from './canonical-json.mjs';
import { canonicalizeResource } from './canonical.mjs';
import { DecisionOutcome } from './decision.mjs';
import { CapabilitySecurityError } from './errors.mjs';
import { normalizeActionRequest, normalizeAgentContext } from './identity.mjs';

// Default session signing secret generated at module load if not provided
const DEFAULT_SESSION_KEY = randomBytes(32).toString('hex');

/**
 * In-memory registry for consumed nonces to prevent replay attacks.
 * Includes automatic expiration cleanup to prevent unbounded growth.
 */
class NonceTracker {
  constructor() {
    /** @type {Map<string, number>} nonce -> expiresAt */
    this.consumed = new Map();
  }

  /**
   * Checks whether a nonce has already been consumed.
   * @param {string} nonce
   * @returns {boolean}
   */
  has(nonce) {
    this.purgeExpired();
    return this.consumed.has(nonce);
  }

  /**
   * Consumes a nonce, marking it as used until expiresAt.
   * @param {string} nonce
   * @param {number} expiresAt Timestamp in ms
   */
  consume(nonce, expiresAt) {
    this.purgeExpired();
    if (this.consumed.has(nonce)) {
      throw new CapabilitySecurityError(
        `Replay attack detected: Nonce "${nonce}" has already been consumed`,
        'REPLAY_ATTACK_DETECTED'
      );
    }
    this.consumed.set(nonce, expiresAt);
  }

  /**
   * Purges nonces that are past their expiration timestamp.
   */
  purgeExpired() {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.consumed.entries()) {
      if (now > expiresAt) {
        this.consumed.delete(nonce);
      }
    }
  }

  /**
   * Clears all consumed nonces (primarily for testing).
   */
  clear() {
    this.consumed.clear();
  }
}

export const globalNonceTracker = new NonceTracker();

/**
 * Computes an HMAC-SHA256 signature for a capability payload.
 *
 * @param {object} payload
 * @param {string} secretKey
 * @returns {string}
 */
export function signCapabilityPayload(payload, secretKey) {
  const canonicalStr = canonicalizeJson(payload);
  return createHmac('sha256', secretKey).update(canonicalStr, 'utf8').digest('hex');
}

/**
 * Issues an ephemeral dynamic capability lease from an approved policy decision.
 *
 * @param {object} params
 * @param {object} params.decision Approved policy decision from evaluatePolicy()
 * @param {object} params.request Action request details
 * @param {object|string} params.context Agent context details
 * @param {object} [params.options]
 * @param {number} [params.options.ttlSeconds=60] Lease lifetime in seconds (1 to 300s)
 * @param {string} [params.options.signingKey] Secret HMAC signing key
 * @returns {object} Deeply immutable Capability Lease
 * @throws {CapabilitySecurityError} If decision is denied or parameters invalid
 */
export function issueCapability({
  decision,
  request,
  context,
  options = {},
}) {
  if (!decision || typeof decision !== 'object') {
    throw new CapabilitySecurityError('Decision object is required to issue capability', 'INVALID_DECISION');
  }

  // Only ALLOW or CONSTRAIN decisions can yield executable capabilities
  if (decision.outcome !== DecisionOutcome.ALLOW && decision.outcome !== DecisionOutcome.CONSTRAIN) {
    throw new CapabilitySecurityError(
      `Cannot issue capability for decision outcome: "${decision.outcome}". Action must be permitted or constrained.`,
      'UNPERMITTED_DECISION'
    );
  }

  const normContext = normalizeAgentContext(context);
  const normRequest = normalizeActionRequest(request);

  const ttlSeconds = typeof options.ttlSeconds === 'number'
    ? Math.max(1, Math.min(300, Math.floor(options.ttlSeconds)))
    : 60;

  const now = Date.now();
  const expiresAt = now + (ttlSeconds * 1000);
  const nonce = randomBytes(16).toString('hex');
  const id = `cap_${randomUUID()}`;
  const signingKey = options.signingKey || DEFAULT_SESSION_KEY;

  const unsignedPayload = {
    id,
    version: '1.0',
    issuer: 'brumm-governance-engine',
    nonce,
    policyHash: decision.policyHash,
    subject: {
      agentId: normContext.agentId,
      taskUid: normContext.taskUid,
      user: normContext.user,
    },
    action: normRequest.action,
    resource: normRequest.canonicalResource,
    constraints: {
      maxBytes: decision.constraints?.absoluteMaxSize ?? null,
      maxObjects: decision.constraints?.absoluteMaxObjects ?? null,
      requireSnapshot: decision.constraints?.requireSnapshot ?? false,
      dryRunOnly: decision.constraints?.dryRunOnly ?? false,
    },
    issuedAt: now,
    expiresAt,
  };

  const signature = signCapabilityPayload(unsignedPayload, signingKey);

  const capability = {
    ...unsignedPayload,
    signature,
  };

  return deepFreeze(capability);
}

/**
 * Verifies the validity, integrity, audience binding, and bounds of a capability lease.
 *
 * @param {object} capability The capability token to verify
 * @param {object} currentPolicy Active compiled policy
 * @param {object} rawRequest Incoming action request
 * @param {object|string} rawContext Incoming agent context
 * @param {object} [options]
 * @param {string} [options.signingKey] Signing key used during issuance
 * @param {NonceTracker} [options.nonceTracker] Optional custom nonce tracker
 * @returns {{ valid: boolean, code?: string, error?: string }}
 */
export function verifyCapability(
  capability,
  currentPolicy,
  rawRequest,
  rawContext,
  options = {}
) {
  if (!capability || typeof capability !== 'object') {
    return { valid: false, code: 'INVALID_CAPABILITY', error: 'Capability must be a non-null object' };
  }

  const signingKey = options.signingKey || DEFAULT_SESSION_KEY;
  const tracker = options.nonceTracker || globalNonceTracker;

  // 1. Verify Cryptographic Signature (Tamper & Forgery Defense)
  const { signature, ...unsignedPayload } = capability;
  if (!signature || typeof signature !== 'string') {
    return { valid: false, code: 'FORGERY_DETECTED', error: 'Missing capability cryptographic signature' };
  }

  const expectedSignature = signCapabilityPayload(unsignedPayload, signingKey);
  if (signature !== expectedSignature) {
    return { valid: false, code: 'FORGERY_DETECTED', error: 'Invalid capability signature: payload has been tampered with or forged' };
  }

  // 2. Verify Expiry (Ephemeral Lease Defense)
  const now = Date.now();
  if (now > capability.expiresAt) {
    return { valid: false, code: 'CAPABILITY_EXPIRED', error: `Capability lease expired at ${capability.expiresAt} (current: ${now})` };
  }

  // 3. Verify Replay (Single-Use Nonce Defense)
  if (tracker.has(capability.nonce)) {
    return { valid: false, code: 'REPLAY_ATTACK_DETECTED', error: `Capability nonce "${capability.nonce}" has already been consumed` };
  }

  // 4. Verify TOCTOU Stale Policy Defense (Policy Hash Binding)
  if (currentPolicy && currentPolicy.hash !== capability.policyHash) {
    return {
      valid: false,
      code: 'STALE_POLICY_REVOKED',
      error: `Policy hash mismatch: capability bound to hash "${capability.policyHash.slice(0, 8)}" but active policy is "${currentPolicy.hash.slice(0, 8)}". Lease revoked due to policy modification.`,
    };
  }

  // 5. Verify Subject / Audience Binding
  const context = normalizeAgentContext(rawContext);
  if (context.agentId !== capability.subject.agentId) {
    return {
      valid: false,
      code: 'AUDIENCE_MISMATCH',
      error: `Capability bound to agent "${capability.subject.agentId}", but invoked by "${context.agentId}"`,
    };
  }

  if (capability.subject.taskUid && context.taskUid !== capability.subject.taskUid) {
    return {
      valid: false,
      code: 'TASK_MISMATCH',
      error: `Capability bound to taskUid "${capability.subject.taskUid}", but invoked by "${context.taskUid}"`,
    };
  }

  // 6. Verify Action & Resource Binding
  let request;
  try {
    request = normalizeActionRequest(rawRequest);
  } catch (err) {
    return { valid: false, code: 'MALFORMED_REQUEST', error: err.message };
  }

  if (request.action !== capability.action) {
    return {
      valid: false,
      code: 'ACTION_MISMATCH',
      error: `Capability permits action "${capability.action}", but request attempted "${request.action}"`,
    };
  }

  if (request.canonicalResource !== capability.resource) {
    return {
      valid: false,
      code: 'RESOURCE_MISMATCH',
      error: `Capability permits resource "${capability.resource}", but request targeted "${request.canonicalResource}"`,
    };
  }

  // 7. Verify Blast Radius Limits Bound in Lease
  if (capability.constraints.maxBytes !== null && request.requestedBytes > capability.constraints.maxBytes) {
    return {
      valid: false,
      code: 'BYTE_LIMIT_EXCEEDED',
      error: `Requested size (${request.requestedBytes}B) exceeds capability lease limit (${capability.constraints.maxBytes}B)`,
    };
  }

  if (capability.constraints.maxObjects !== null && request.requestedCount > capability.constraints.maxObjects) {
    return {
      valid: false,
      code: 'OBJECT_LIMIT_EXCEEDED',
      error: `Requested object count (${request.requestedCount}) exceeds capability lease limit (${capability.constraints.maxObjects})`,
    };
  }

  if (capability.constraints.requireSnapshot && !request.hasSnapshot) {
    return {
      valid: false,
      code: 'SNAPSHOT_REQUIRED',
      error: 'Capability requires pre-execution snapshot before invocation',
    };
  }

  if (capability.constraints.dryRunOnly && !request.isDryRun) {
    return {
      valid: false,
      code: 'DRY_RUN_REQUIRED',
      error: 'Capability permits dry-run execution only',
    };
  }

  return { valid: true };
}

/**
 * Atomically consumes a capability lease nonce, preventing replay attacks.
 *
 * @param {object} capability
 * @param {object} [options]
 * @param {NonceTracker} [options.nonceTracker]
 */
export function consumeCapability(capability, options = {}) {
  const tracker = options.nonceTracker || globalNonceTracker;
  if (!capability || !capability.nonce || !capability.expiresAt) {
    throw new CapabilitySecurityError('Invalid capability token for consumption', 'INVALID_CAPABILITY');
  }
  tracker.consume(capability.nonce, capability.expiresAt);
}
