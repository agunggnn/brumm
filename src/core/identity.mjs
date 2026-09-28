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

  if (typeof request.resource !== 'string' || request.resource.trim().length === 0) {
    throw new TypeError('Resource must be a non-empty string');
  }

  const action = request.action.trim().toLowerCase();
  const canonical = canonicalizeResource(request.resource);

  // Normalize requested bytes
  let requestedBytes = 0;
  if (request.requestedBytes !== undefined && request.requestedBytes !== null) {
    requestedBytes = parseByteSize(request.requestedBytes);
  } else if (request.size !== undefined && request.size !== null) {
    requestedBytes = parseByteSize(request.size);
  }

  // Normalize requested count
  const requestedCount = typeof request.requestedCount === 'number'
    ? Math.max(0, Math.floor(request.requestedCount))
    : (typeof request.count === 'number' ? Math.max(0, Math.floor(request.count)) : 1);

  return {
    action,
    rawResource: request.resource,
    canonicalResource: canonical.uri,
    resourcePath: canonical.path,
    resourceScheme: canonical.scheme,
    requestedBytes,
    requestedCount,
    hasSnapshot: Boolean(request.hasSnapshot || request.snapshot),
    isDryRun: Boolean(request.isDryRun || request.dryRun),
    justification: typeof request.justification === 'string' ? request.justification.trim() : '',
    parameters: request.parameters && typeof request.parameters === 'object' ? { ...request.parameters } : {},
  };
}
