/**
 * @file src/core/index.mjs
 * Core exports for the Brumm Agentic Governance Engine.
 */

export {
  canonicalizeJson,
  computeCanonicalSha256,
  deepFreeze,
} from './canonical-json.mjs';
export { canonicalizeResource, matchResourcePattern } from './canonical.mjs';
export {
  DecisionOutcome,
  PrecedenceRank,
  ValidDefaultEffects,
  ValidEffects,
  createDecision,
  parseByteSize,
} from './decision.mjs';
export {
  PolicyValidationError,
  ResourceCanonicalizationError,
} from './errors.mjs';
export { normalizeActionRequest, normalizeAgentContext } from './identity.mjs';
export { evaluatePolicy } from './policy-engine.mjs';
export {
  compilePolicy,
  loadPolicyFile,
  parseYamlSubset,
  validatePolicySchema,
} from './policy-loader.mjs';
