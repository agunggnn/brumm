/**
 * @file capability.mjs
 * Dynamic Capability Engine (JEV Primitive) for Brumm.
 * Issues ephemeral, audience-bound, cryptographically signed capability leases
 * with atomic single-use nonce consumption and TOCTOU policy-hash binding.
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { canonicalizeJson, deepFreeze } from './canonical-json.mjs';
import { canonicalizeResource } from './canonical.mjs';
import { DecisionOutcome } from './decision.mjs';
import { CapabilitySecurityError } from './errors.mjs';
import { normalizeActionRequest, normalizeAgentContext } from './identity.mjs';

let devEphemeralKey = null;

/**
 * Resolves the HMAC-SHA256 signing key.
 * In production mode, an explicit key is mandatory (min 32 chars) to prevent
 * process-restart token invalidation or cross-process verification failures.
 *
 * @param {string} [providedKey]
 * @param {boolean} [isProduction]
 * @returns {string}
 */
export function resolveSigningKey(
  providedKey,
  isProduction = process.env.NODE_ENV === 'production'
) {
  if (providedKey && typeof providedKey === 'string' && providedKey.trim().length >= 32) {
    return providedKey.trim();
  }

  const envKey = process.env.BRUMM_SIGNING_KEY;
  if (envKey && envKey.trim().length >= 32) {
    return envKey.trim();
  }

  if (isProduction) {
    throw new CapabilitySecurityError(
      'Production security violation: BRUMM_SIGNING_KEY environment variable or options.signingKey (min 32 characters) is mandatory in production mode. Ephemeral keys are strictly forbidden.',
      'MISSING_SIGNING_KEY'
    );
  }

  // Development / Test fallback
  if (!devEphemeralKey) {
    devEphemeralKey = randomBytes(32).toString('hex');
  }
  return devEphemeralKey;
}

/**
 * In-memory registry for consumed nonces to prevent replay attacks.
 * Includes automatic expiration cleanup to prevent unbounded growth.
 *
 * ARCHITECTURAL NOTICE / DISTRIBUTED DEPLOYMENT CAVEAT:
 * This NonceTracker implementation is strictly process-local (single Node.js event loop).
 * In distributed, multi-replica, or serverless architectures, process-local memory cannot
 * prevent replay across different worker processes or nodes.
 *
 * TODO(architecture): For distributed production clusters:
 * Implement a distributed atomic nonce store backed by a distributed CAS (Compare-And-Swap)
 * or atomic key-value store (e.g. Redis `SET key 1 NX PX <ttlMs>`, DynamoDB conditional put,
 * or Memcached `add`).
 */
export class NonceTracker {
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
   * Atomically checks and consumes a nonce in a single synchronous operation.
   * Prevents TOCTOU race conditions between concurrent verifications.
   *
   * @param {string} nonce
   * @param {number} expiresAt Timestamp in ms
   * @returns {boolean} true if successfully consumed, false if already consumed
   */
  atomicConsume(nonce, expiresAt) {
    this.purgeExpired();
    if (this.consumed.has(nonce)) {
      return false;
    }
    this.consumed.set(nonce, expiresAt);
    return true;
  }

  /**
   * Consumes a nonce, throwing an error if already consumed.
   * @param {string} nonce
   * @param {number} expiresAt Timestamp in ms
   */
  consume(nonce, expiresAt) {
    const success = this.atomicConsume(nonce, expiresAt);
    if (!success) {
      throw new CapabilitySecurityError(
        `Replay attack detected: Nonce "${nonce}" has already been consumed`,
        'REPLAY_ATTACK_DETECTED'
      );
    }
  }

  /**
   * Purges nonces that are past their expiration timestamp.
   * Lease is considered invalid/expired when now >= expiresAt.
   */
  purgeExpired() {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.consumed.entries()) {
      if (now >= expiresAt) {
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
 * @throws {CapabilitySecurityError} If decision is denied or constraints unfulfilled
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

  // 1. Only ALLOW or CONSTRAIN decisions can yield capabilities
  if (decision.outcome !== DecisionOutcome.ALLOW && decision.outcome !== DecisionOutcome.CONSTRAIN) {
    throw new CapabilitySecurityError(
      `Cannot issue capability for decision outcome: "${decision.outcome}". Action must be permitted or constrained.`,
      'UNPERMITTED_DECISION'
    );
  }

  const normContext = normalizeAgentContext(context);
  const normRequest = normalizeActionRequest(request);

  // 2. Enforce CONSTRAIN transformation prerequisites
  if (decision.outcome === DecisionOutcome.CONSTRAIN) {
    if (decision.constraints?.requireSnapshot && !normRequest.hasSnapshot) {
      throw new CapabilitySecurityError(
        'Cannot issue execution capability for CONSTRAIN decision: prerequisite transformation step (SNAPSHOT) has not been completed. Create snapshot before requesting execution capability.',
        'PREREQUISITE_TRANSFORMATION_REQUIRED'
      );
    }

    if (decision.constraints?.dryRunOnly && !normRequest.isDryRun) {
      throw new CapabilitySecurityError(
        'Cannot issue execution capability for CONSTRAIN decision: dry-run verification is required before live execution.',
        'DRY_RUN_VERIFICATION_REQUIRED'
      );
    }
  }

  const ttlSeconds = typeof options.ttlSeconds === 'number'
    ? Math.max(1, Math.min(300, Math.floor(options.ttlSeconds)))
    : 60;

  const now = Date.now();
  const expiresAt = now + (ttlSeconds * 1000);
  const nonce = randomBytes(16).toString('hex');
  const id = `cap_${randomUUID()}`;
  const signingKey = resolveSigningKey(options.signingKey);

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
 * When consume is true (default), atomically checks and consumes the nonce.
 *
 * @param {object} capability The capability token to verify
 * @param {object} currentPolicy Active compiled policy
 * @param {object} rawRequest Incoming action request
 * @param {object|string} rawContext Incoming agent context
 * @param {object} [options]
 * @param {string} [options.signingKey] Signing key used during issuance
 * @param {boolean} [options.consume=false] Whether to atomically consume the nonce during verification
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
  // 1. Structural Schema Validation
  if (!capability || typeof capability !== 'object' || Array.isArray(capability)) {
    return { valid: false, code: 'INVALID_CAPABILITY', error: 'Capability must be a non-null object' };
  }

  if (capability.version !== '1.0') {
    return {
      valid: false,
      code: 'INVALID_VERSION',
      error: `Unsupported capability version: "${capability.version}". Expected "1.0"`,
    };
  }

  if (capability.issuer !== 'brumm-governance-engine') {
    return {
      valid: false,
      code: 'INVALID_ISSUER',
      error: `Invalid capability issuer: "${capability.issuer}". Expected "brumm-governance-engine"`,
    };
  }

  if (typeof capability.id !== 'string' || !capability.id.startsWith('cap_')) {
    return {
      valid: false,
      code: 'MALFORMED_CAPABILITY',
      error: 'Capability ID must be a string starting with "cap_"',
    };
  }

  if (typeof capability.nonce !== 'string' || !/^[0-9a-f]{16,}$/i.test(capability.nonce)) {
    return {
      valid: false,
      code: 'MALFORMED_NONCE',
      error: 'Capability nonce must be a hex string of at least 16 characters',
    };
  }

  if (typeof capability.policyHash !== 'string' || !/^[0-9a-f]{64}$/i.test(capability.policyHash)) {
    return {
      valid: false,
      code: 'MALFORMED_POLICY_HASH',
      error: 'Capability policyHash must be a 64-character hex SHA-256 digest',
    };
  }

  if (
    !capability.subject ||
    typeof capability.subject !== 'object' ||
    Array.isArray(capability.subject) ||
    typeof capability.subject.agentId !== 'string' ||
    capability.subject.agentId.trim().length === 0 ||
    typeof capability.subject.user !== 'string' ||
    capability.subject.user.trim().length === 0 ||
    (capability.subject.taskUid !== undefined &&
      capability.subject.taskUid !== null &&
      typeof capability.subject.taskUid !== 'string')
  ) {
    return {
      valid: false,
      code: 'MALFORMED_SUBJECT',
      error: 'Capability subject must contain valid agentId, user, and optional taskUid',
    };
  }

  if (typeof capability.action !== 'string' || capability.action.trim().length === 0) {
    return {
      valid: false,
      code: 'MALFORMED_ACTION',
      error: 'Capability action must be a non-empty string',
    };
  }

  if (typeof capability.resource !== 'string' || capability.resource.trim().length === 0) {
    return {
      valid: false,
      code: 'MALFORMED_RESOURCE',
      error: 'Capability resource must be a non-empty string',
    };
  }

  if (!capability.constraints || typeof capability.constraints !== 'object' || Array.isArray(capability.constraints)) {
    return {
      valid: false,
      code: 'MALFORMED_CONSTRAINTS',
      error: 'Capability constraints must be an object',
    };
  }

  // 2. Timestamp & Invariant Validation
  if (
    !Number.isSafeInteger(capability.issuedAt) ||
    capability.issuedAt <= 0 ||
    !Number.isSafeInteger(capability.expiresAt) ||
    capability.expiresAt <= 0
  ) {
    return {
      valid: false,
      code: 'MALFORMED_TIMESTAMPS',
      error: 'Capability timestamps (issuedAt, expiresAt) must be positive safe integers',
    };
  }

  if (capability.expiresAt <= capability.issuedAt) {
    return {
      valid: false,
      code: 'INVALID_TIME_INVARIANT',
      error: `Capability expiresAt (${capability.expiresAt}) must be strictly greater than issuedAt (${capability.issuedAt})`,
    };
  }

  const ttlMs = capability.expiresAt - capability.issuedAt;
  if (ttlMs < 1000 || ttlMs > 300000) {
    return {
      valid: false,
      code: 'INVALID_TIME_INVARIANT',
      error: `Capability TTL (${ttlMs}ms) is outside permissible bounds (1000ms - 300000ms)`,
    };
  }

  // 3. Cryptographic Signature Verification (Tamper & Forgery Defense)
  if (typeof capability.signature !== 'string' || !/^[0-9a-f]{64}$/i.test(capability.signature)) {
    return {
      valid: false,
      code: 'FORGERY_DETECTED',
      error: 'Missing or malformed capability cryptographic signature',
    };
  }

  const signingKey = resolveSigningKey(options.signingKey);
  const tracker = options.nonceTracker || globalNonceTracker;

  const { signature, ...unsignedPayload } = capability;
  const expectedSignature = signCapabilityPayload(unsignedPayload, signingKey);

  const sigBuf = Buffer.from(signature, 'hex');
  const expBuf = Buffer.from(expectedSignature, 'hex');
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    return {
      valid: false,
      code: 'FORGERY_DETECTED',
      error: 'Invalid capability signature: payload has been tampered with or forged',
    };
  }

  // 4. Verify Expiry (Ephemeral Lease Defense)
  const now = Date.now();
  if (now >= capability.expiresAt) {
    return {
      valid: false,
      code: 'CAPABILITY_EXPIRED',
      error: `Capability lease expired at ${capability.expiresAt} (current: ${now})`,
    };
  }

  // 5. Verify TOCTOU Stale Policy Defense (Policy Hash Binding)
  if (currentPolicy && currentPolicy.hash !== capability.policyHash) {
    return {
      valid: false,
      code: 'STALE_POLICY_REVOKED',
      error: `Policy hash mismatch: capability bound to hash "${capability.policyHash.slice(0, 8)}" but active policy is "${currentPolicy.hash.slice(0, 8)}". Lease revoked due to policy modification.`,
    };
  }

  // 6. Verify Subject / Audience Binding
  let context;
  try {
    context = normalizeAgentContext(rawContext);
  } catch (err) {
    return {
      valid: false,
      code: 'MALFORMED_CONTEXT',
      error: `Malformed agent context: ${err.message}`,
    };
  }

  if (context.agentId !== capability.subject.agentId) {
    return {
      valid: false,
      code: 'AUDIENCE_MISMATCH',
      error: `Capability bound to agent "${capability.subject.agentId}", but invoked by "${context.agentId}"`,
    };
  }

  if (capability.subject.user && context.user !== capability.subject.user) {
    return {
      valid: false,
      code: 'USER_MISMATCH',
      error: `Capability bound to user "${capability.subject.user}", but invoked by "${context.user}"`,
    };
  }

  if (capability.subject.taskUid && context.taskUid !== capability.subject.taskUid) {
    return {
      valid: false,
      code: 'TASK_MISMATCH',
      error: `Capability bound to taskUid "${capability.subject.taskUid}", but invoked by "${context.taskUid}"`,
    };
  }

  // 7. Verify Action & Resource Binding
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

  // 8. Verify Blast Radius Limits Bound in Lease
  if (capability.constraints.maxBytes !== null) {
    if (request.requestedBytes === null || request.requestedBytes === undefined) {
      return {
        valid: false,
        code: 'BYTE_MEASUREMENT_REQUIRED',
        error: `Capability lease bounds byte limit (${capability.constraints.maxBytes}B), but request omitted byte size measurement`,
      };
    }
    if (request.requestedBytes > capability.constraints.maxBytes) {
      return {
        valid: false,
        code: 'BYTE_LIMIT_EXCEEDED',
        error: `Requested size (${request.requestedBytes}B) exceeds capability lease limit (${capability.constraints.maxBytes}B)`,
      };
    }
  }

  if (capability.constraints.maxObjects !== null) {
    if (request.requestedCount === null || request.requestedCount === undefined) {
      return {
        valid: false,
        code: 'OBJECT_MEASUREMENT_REQUIRED',
        error: `Capability lease bounds object count limit (${capability.constraints.maxObjects}), but request omitted object count measurement`,
      };
    }
    if (request.requestedCount > capability.constraints.maxObjects) {
      return {
        valid: false,
        code: 'OBJECT_LIMIT_EXCEEDED',
        error: `Requested object count (${request.requestedCount}) exceeds capability lease limit (${capability.constraints.maxObjects})`,
      };
    }
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

  // 9. Atomic Replay Check / Consumption
  if (options.consume === true) {
    const consumed = tracker.atomicConsume(capability.nonce, capability.expiresAt);
    if (!consumed) {
      return {
        valid: false,
        code: 'REPLAY_ATTACK_DETECTED',
        error: `Capability nonce "${capability.nonce}" has already been consumed (replay attack blocked)`,
      };
    }
  } else {
    // Read-only check without consuming
    if (tracker.has(capability.nonce)) {
      return {
        valid: false,
        code: 'REPLAY_ATTACK_DETECTED',
        error: `Capability nonce "${capability.nonce}" has already been consumed`,
      };
    }
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
