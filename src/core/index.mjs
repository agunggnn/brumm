/**
 * @file src/core/index.mjs
 * Core exports for the Brumm Agentic Governance Engine.
 */

export {
  canonicalizeJson,
  computeCanonicalSha256,
  deepFreeze,
  isDeepFrozen,
} from './canonical-json.mjs';
export { canonicalizeResource, matchResourcePattern, safePercentDecode } from './canonical.mjs';
export {
  consumeCapability,
  globalNonceTracker,
  issueCapability,
  signCapabilityPayload,
  verifyCapability,
} from './capability.mjs';
export {
  DecisionOutcome,
  PrecedenceRank,
  ValidDefaultEffects,
  ValidEffects,
  createDecision,
  parseByteSize,
} from './decision.mjs';
export {
  CapabilitySecurityError,
  ExecutionSecurityError,
  PolicyValidationError,
  ResourceCanonicalizationError,
} from './errors.mjs';
export { normalizeActionRequest, normalizeAgentContext } from './identity.mjs';
export { evaluatePolicy } from './policy-engine.mjs';
export {
  compilePolicy,
  computePolicyHash,
  isCompiledPolicy,
  loadPolicyFile,
  parseYamlSubset,
  validatePolicySchema,
} from './policy-loader.mjs';
