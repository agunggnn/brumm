/**
 * @file src/core/index.mjs
 * Core exports for the Brumm Agentic Governance Engine.
 */

export { canonicalizeResource, matchResourcePattern } from './canonical.mjs';
export {
  DecisionOutcome,
  PrecedenceRank,
  parseByteSize,
  createDecision,
} from './decision.mjs';
export { normalizeAgentContext, normalizeActionRequest } from './identity.mjs';
export {
  compilePolicy,
  computePolicyHash,
  loadPolicyFile,
  parseYamlSubset,
} from './policy-loader.mjs';
export { evaluatePolicy } from './policy-engine.mjs';
