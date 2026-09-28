/**
 * @file identity.mjs
 * Agent identity and request normalization.
 */

import { canonicalizeResource } from './canonical.mjs';
import { parseByteSize } from './decision.mjs';

/**
 * Normalizes agent context for policy evaluation.
 *
 * @param {object|string} context
 * @returns {object}
 */
export function normalizeAgentContext(context) {
  if (typeof context === 'string') {
    return {
      agentId: context.trim(),
      environment: 'development',
      user: 'unknown',
      taskUid: null,
      metadata: {},
    };
  }

  if (!context || typeof context !== 'object') {
    throw new TypeError('Agent context must be a non-null object or string');
  }

  const agentId = typeof context.agentId === 'string' && context.agentId.trim().length > 0
    ? context.agentId.trim()
    : 'anonymous-agent';

  const environment = typeof context.environment === 'string' && context.environment.trim().length > 0
    ? context.environment.trim().toLowerCase()
    : 'development';

  const user = typeof context.user === 'string' && context.user.trim().length > 0
    ? context.user.trim()
    : 'system';

  const taskUid = typeof context.taskUid === 'string' && context.taskUid.trim().length > 0
    ? context.taskUid.trim()
    : null;

  return {
    agentId,
    environment,
    user,
    taskUid,
    metadata: context.metadata && typeof context.metadata === 'object' ? { ...context.metadata } : {},
  };
}

/**
 * Normalizes an incoming action request.
 *
 * @param {object} request
 * @returns {object}
 */
export function normalizeActionRequest(request) {
  if (!request || typeof request !== 'object') {
    throw new TypeError('Action request must be a non-null object');
  }

  if (typeof request.action !== 'string' || request.action.trim().length === 0) {
    throw new TypeError('Action must be a non-empty string');
  }

  const rawResource = typeof request.resource === 'string'
    ? request.resource
    : (typeof request.rawResource === 'string' ? request.rawResource : null);

  if (!rawResource || rawResource.trim().length === 0) {
    throw new TypeError('Resource must be a non-empty string');
  }

  const action = request.action.trim().toLowerCase();
  const canonical = canonicalizeResource(rawResource);

  // Normalize requested bytes: null if omitted, strict parsing if present
  let requestedBytes = null;
  const rawSize = request.requestedBytes !== undefined ? request.requestedBytes : request.size;
  if (rawSize !== undefined && rawSize !== null) {
    requestedBytes = parseByteSize(rawSize);
  }

  // Normalize requested count strictly: null if omitted, safe integer if present
  let requestedCount = null;
  const rawCount = request.requestedCount !== undefined ? request.requestedCount : request.count;

  if (rawCount !== undefined && rawCount !== null) {
    if (typeof rawCount === 'number') {
      if (!Number.isSafeInteger(rawCount) || rawCount < 0) {
        throw new TypeError(`Invalid requested object count: ${rawCount}. Must be a safe non-negative integer.`);
      }
      requestedCount = rawCount;
    } else if (typeof rawCount === 'string') {
      const trimmed = rawCount.trim();
      if (!/^[0-9]+$/.test(trimmed)) {
        throw new TypeError(`Invalid requested object count string: "${rawCount}". Expected digits only.`);
      }
      const parsed = Number(trimmed);
      if (!Number.isSafeInteger(parsed) || parsed < 0) {
        throw new TypeError(`Invalid requested object count string: "${rawCount}". Exceeds safe integer range.`);
      }
      requestedCount = parsed;
    } else {
      throw new TypeError(`Invalid requested object count type: ${typeof rawCount}. Must be a safe non-negative integer or digit string.`);
    }
  }

  // Strict boolean validation (reject "false", "true", 0, 1, etc.)
  function parseStrictBoolean(primary, secondary, primaryName, secondaryName) {
    if (primary !== undefined && primary !== null && typeof primary !== 'boolean') {
      throw new TypeError(`Field "${primaryName}" must be a boolean (true or false), received ${typeof primary}`);
    }
    if (secondary !== undefined && secondary !== null && typeof secondary !== 'boolean') {
      throw new TypeError(`Field "${secondaryName}" must be a boolean (true or false), received ${typeof secondary}`);
    }
    if (primary !== undefined && primary !== null) {
      return primary;
    }
    if (secondary !== undefined && secondary !== null) {
      return secondary;
    }
    return false;
  }

  const hasSnapshot = parseStrictBoolean(request.hasSnapshot, request.snapshot, 'hasSnapshot', 'snapshot');
  const isDryRun = parseStrictBoolean(request.isDryRun, request.dryRun, 'isDryRun', 'dryRun');

  return {
    action,
    resource: rawResource,
    rawResource,
    canonicalResource: canonical.uri,
    resourcePath: canonical.path,
    resourceScheme: canonical.scheme,
    requestedBytes,
    requestedCount,
    hasSnapshot,
    isDryRun,
    justification: typeof request.justification === 'string' ? request.justification.trim() : '',
    parameters: request.parameters && typeof request.parameters === 'object' ? { ...request.parameters } : {},
  };
}
