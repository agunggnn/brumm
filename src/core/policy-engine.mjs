/**
 * @file policy-engine.mjs
 * Deterministic Policy Evaluation Engine with strict precedence hierarchy.
 * Evaluates requests against compiled policy trees with sub-millisecond execution.
 */

import { matchResourcePattern } from './canonical.mjs';
import {
  DecisionOutcome,
  PrecedenceRank,
  createDecision,
} from './decision.mjs';
import { normalizeActionRequest, normalizeAgentContext } from './identity.mjs';

/**
 * Checks if a string pattern (supporting wildcards '*' and '?') matches a target string.
 *
 * @param {string} pattern
 * @param {string} target
 * @returns {boolean}
 */
function matchStringPattern(pattern, target) {
  if (pattern === '*' || pattern === '') return true;
  if (pattern === target) return true;

  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');

  return new RegExp(`^${regexStr}$`, 'i').test(target);
}

/**
 * Evaluates an action request against a compiled policy.
 *
 * @param {object} compiledPolicy Output of compilePolicy() or loadPolicyFile()
 * @param {object} rawRequest Action request details
 * @param {object|string} [rawContext] Agent context or agentId string
 * @returns {object} Structured Policy Decision
 */
export function evaluatePolicy(compiledPolicy, rawRequest, rawContext = {}) {
  if (!compiledPolicy || typeof compiledPolicy !== 'object' || !Array.isArray(compiledPolicy.rules)) {
    throw new TypeError('compiledPolicy must be a valid compiled policy object');
  }

  const context = normalizeAgentContext(rawContext);
  let request;

  try {
    request = normalizeActionRequest(rawRequest);
  } catch (err) {
    // If request normalization fails (e.g. traversal attempt), immediately DENY
    return createDecision({
      outcome: DecisionOutcome.DENY,
      reasons: [`Invalid or malformed action request: ${err.message}`],
      policyHash: compiledPolicy.hash,
    });
  }

  const candidateDecisions = [];

  for (const rule of compiledPolicy.rules) {
    // 1. Match agent pattern
    if (!matchStringPattern(rule.agentPattern, context.agentId)) {
      continue;
    }

    // 2. Match environment pattern
    if (!matchStringPattern(rule.environmentPattern, context.environment)) {
      continue;
    }

    // 3. Match action pattern
    if (!matchStringPattern(rule.actionPattern, request.action)) {
      continue;
    }

    // 4. Match resource pattern against canonical URI
    if (!matchResourcePattern(request.canonicalResource, rule.resourcePattern)) {
      continue;
    }

    // --- Rule matches! Now evaluate constraints & effect ---
    const constraints = rule.constraints || {};
    const reasons = [...rule.reasons];
    let effectiveRank = PrecedenceRank.ALLOW;
    let outcome = rule.effect;
    let suggestedTransform = null;

    // Check critical resource protection
    if (rule.isCriticalProtection) {
      effectiveRank = PrecedenceRank.CRITICAL_RESOURCE;
      outcome = DecisionOutcome.DENY;
      reasons.push(`Target resource "${request.canonicalResource}" is classified as a protected critical asset`);
    } else if (rule.effect === DecisionOutcome.DENY) {
      effectiveRank = PrecedenceRank.EXPLICIT_DENY;
      outcome = DecisionOutcome.DENY;
      if (reasons.length === 0) {
        reasons.push(`Action "${request.action}" on "${request.canonicalResource}" explicitly denied by rule "${rule.id}"`);
      }
    } else if (rule.effect === DecisionOutcome.ESCALATE) {
      effectiveRank = PrecedenceRank.ESCALATE;
      outcome = DecisionOutcome.ESCALATE;
    } else {
      // Evaluate constraints on ALLOW or CONSTRAIN rules
      // A. Check approval escalation threshold (e.g. size exceeds autonomous limit)
      if (
        constraints.requireApprovalAbove !== null &&
        request.requestedBytes > constraints.requireApprovalAbove
      ) {
        effectiveRank = PrecedenceRank.ESCALATE;
        outcome = DecisionOutcome.ESCALATE;
        reasons.push(
          `Requested size (${request.requestedBytes} bytes) exceeds autonomous approval threshold (${constraints.requireApprovalAbove} bytes)`
        );
      }
      // B. Check hard max size cap
      else if (
        constraints.maxBytes !== null &&
        request.requestedBytes > constraints.maxBytes
      ) {
        effectiveRank = PrecedenceRank.EXPLICIT_DENY;
        outcome = DecisionOutcome.DENY;
        reasons.push(
          `Requested size (${request.requestedBytes} bytes) exceeds maximum allowable limit (${constraints.maxBytes} bytes)`
        );
      }
      // C. Check snapshot requirement
      else if (constraints.requireSnapshot && !request.hasSnapshot) {
        effectiveRank = PrecedenceRank.CONSTRAIN;
        outcome = DecisionOutcome.CONSTRAIN;
        reasons.push('Pre-execution snapshot is required before proceeding with destructive action');
        suggestedTransform = {
          step: 'SNAPSHOT',
          target: request.canonicalResource,
          pipeline: ['SNAPSHOT', 'DRY_RUN', 'EXECUTE'],
        };
      }
      // D. Check dry-run requirement
      else if (constraints.dryRunOnly && !request.isDryRun) {
        effectiveRank = PrecedenceRank.CONSTRAIN;
        outcome = DecisionOutcome.CONSTRAIN;
        reasons.push('Dry-run verification is required for this action');
        suggestedTransform = {
          step: 'DRY_RUN',
          target: request.canonicalResource,
          pipeline: ['DRY_RUN', 'VERIFY'],
        };
      } else {
        effectiveRank = PrecedenceRank.ALLOW;
        outcome = DecisionOutcome.ALLOW;
        if (reasons.length === 0) {
          reasons.push(`Action permitted under rule "${rule.id}"`);
        }
      }
    }

    candidateDecisions.push({
      rank: effectiveRank,
      outcome,
      reasons,
      ruleId: rule.id,
      constraints,
      suggestedTransform,
    });
  }

  // If no rules matched, apply default effect
  if (candidateDecisions.length === 0) {
    const isDefaultAllow = compiledPolicy.defaultEffect === DecisionOutcome.ALLOW;
    return createDecision({
      outcome: isDefaultAllow ? DecisionOutcome.ALLOW : DecisionOutcome.DENY,
      reasons: [
        isDefaultAllow
          ? 'No explicit rules matched; default-allow policy applied'
          : `Default-deny: No rule permitted action "${request.action}" for agent "${context.agentId}" on "${request.canonicalResource}"`,
      ],
      matchedRule: null,
      policyHash: compiledPolicy.hash,
    });
  }

  // Sort candidate decisions by Precedence Rank descending (highest rank wins)
  candidateDecisions.sort((a, b) => b.rank - a.rank);

  const winningDecision = candidateDecisions[0];

  return createDecision({
    outcome: winningDecision.outcome,
    reasons: winningDecision.reasons,
    matchedRule: winningDecision.ruleId,
    policyHash: compiledPolicy.hash,
    constraints: winningDecision.constraints,
    suggestedTransform: winningDecision.suggestedTransform,
  });
}
