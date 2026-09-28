/**
 * @file src/index.mjs
 * Main entry point for @agunggnn/brumm.
 * Provides the primary programmatic API: createGuard() and createExecutionGuard()
 */

import { createExecutionGuard } from './adapters/tool-adapter.mjs';
import {
  canonicalizeJson,
  computeCanonicalSha256,
  deepFreeze,
} from './core/canonical-json.mjs';
import {
  canonicalizeResource,
  matchResourcePattern,
  safePercentDecode,
} from './core/canonical.mjs';
import {
  consumeCapability,
  globalNonceTracker,
  issueCapability,
  signCapabilityPayload,
  verifyCapability,
} from './core/capability.mjs';
import {
  DecisionOutcome,
  PrecedenceRank,
  ValidDefaultEffects,
  ValidEffects,
  createDecision,
  parseByteSize,
} from './core/decision.mjs';
import {
  CapabilitySecurityError,
  ExecutionSecurityError,
  PolicyValidationError,
  ResourceCanonicalizationError,
} from './core/errors.mjs';
import {
  normalizeActionRequest,
  normalizeAgentContext,
} from './core/identity.mjs';
import { evaluatePolicy } from './core/policy-engine.mjs';
import {
  compilePolicy,
  loadPolicyFile,
  validatePolicySchema,
} from './core/policy-loader.mjs';

/**
 * Creates a Brumm governance guard instance.
 *
 * @param {object} options
 * @param {string|object} options.policy Path to YAML/JSON policy file or policy object
 * @param {string} [options.agent] Default agent identifier
 * @param {string} [options.environment] Default environment (e.g. 'production', 'development')
 * @returns {object} Guard instance
 */
export function createGuard(options = {}) {
  let policy;

  if (typeof options.policy === 'string') {
    policy = loadPolicyFile(options.policy);
  } else if (options.policy && typeof options.policy === 'object') {
    policy = compilePolicy(options.policy);
  } else {
    throw new TypeError('options.policy must be a valid file path string or policy object');
  }

  const defaultAgent = options.agent || 'default-agent';
  const defaultEnvironment = options.environment || 'development';

  return {
    /**
     * Active compiled, deeply immutable policy.
     */
    get policy() {
      return policy;
    },

    /**
     * SHA-256 fingerprint of the loaded policy.
     */
    get policyHash() {
      return policy.hash;
    },

    /**
     * Evaluates an agent action request against the guard policy.
     *
     * @param {object} request Action request details
     * @param {object|string} [contextOverride] Optional context override
     * @returns {object} Policy Decision
     */
    evaluate(request, contextOverride = {}) {
      const mergedContext = {
        agentId: defaultAgent,
        environment: defaultEnvironment,
        ...(typeof contextOverride === 'string' ? { agentId: contextOverride } : contextOverride),
      };
      return evaluatePolicy(policy, request, mergedContext);
    },
  };
}

// Re-export core modules & adapters
export {
  createExecutionGuard,
  issueCapability,
  verifyCapability,
  consumeCapability,
  globalNonceTracker,
  signCapabilityPayload,
  canonicalizeResource,
  matchResourcePattern,
  safePercentDecode,
  canonicalizeJson,
  computeCanonicalSha256,
  deepFreeze,
  compilePolicy,
  loadPolicyFile,
  validatePolicySchema,
  evaluatePolicy,
  createDecision,
  DecisionOutcome,
  PrecedenceRank,
  ValidEffects,
  ValidDefaultEffects,
  parseByteSize,
  normalizeAgentContext,
  normalizeActionRequest,
  PolicyValidationError,
  ResourceCanonicalizationError,
  CapabilitySecurityError,
  ExecutionSecurityError,
};
