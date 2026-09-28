/**
 * @file decision.mjs
 * Policy decision outcomes, rule effects, and precedence definitions.
 */

/**
 * Enumeration of possible policy decision outcomes.
 * @readonly
 * @enum {string}
 */
export const DecisionOutcome = {
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  CONSTRAIN: 'CONSTRAIN',
  ESCALATE: 'ESCALATE',
};

/**
 * Precedence ranks for resolving conflicting rules.
 * Higher number = higher precedence.
 *
 * Precedence Order:
 *   1. EXPLICIT_DENY (100)
 *   2. CRITICAL_RESOURCE_PROTECTION (90)
 *   3. ESCALATE / APPROVAL_REQUIRED (80)
 *   4. CONSTRAIN / SCOPE_LIMITS (70)
 *   5. ALLOW (60)
 *   6. DEFAULT_DENY (10)
 */
export const PrecedenceRank = {
  EXPLICIT_DENY: 100,
  CRITICAL_RESOURCE: 90,
  ESCALATE: 80,
  CONSTRAIN: 70,
  ALLOW: 60,
  DEFAULT_DENY: 10,
};

/**
 * Parses a byte size string (e.g. "50GB", "500MB", "10KB", "1024") into numeric bytes.
 *
 * @param {string|number} sizeStr
 * @returns {number}
 */
export function parseByteSize(sizeStr) {
  if (typeof sizeStr === 'number') {
    return Math.max(0, Math.floor(sizeStr));
  }
  if (typeof sizeStr !== 'string') {
    return 0;
  }

  const trimmed = sizeStr.trim().toUpperCase();
  const match = trimmed.match(/^([0-9]+(?:\.[0-9]+)?)\s*([A-Z]*)$/);
  if (!match) {
    return 0;
  }

  const val = parseFloat(match[1]);
  const unit = match[2];

  switch (unit) {
    case 'TB':
    case 'TIB':
      return Math.floor(val * 1024 * 1024 * 1024 * 1024);
    case 'GB':
    case 'GIB':
      return Math.floor(val * 1024 * 1024 * 1024);
    case 'MB':
    case 'MIB':
      return Math.floor(val * 1024 * 1024);
    case 'KB':
    case 'KIB':
      return Math.floor(val * 1024);
    case 'B':
    case '':
      return Math.floor(val);
    default:
      return Math.floor(val);
  }
}

/**
 * Creates a structured policy decision object.
 *
 * @param {object} params
 * @param {keyof typeof DecisionOutcome} params.outcome
 * @param {string[]} params.reasons
 * @param {string|null} [params.matchedRule]
 * @param {string|null} [params.policyHash]
 * @param {object|null} [params.constraints]
 * @param {object|null} [params.suggestedTransform]
 * @returns {object}
 */
export function createDecision({
  outcome,
  reasons = [],
  matchedRule = null,
  policyHash = null,
  constraints = null,
  suggestedTransform = null,
}) {
  return {
    outcome,
    allowed: outcome === DecisionOutcome.ALLOW,
    requiresApproval: outcome === DecisionOutcome.ESCALATE,
    isConstrained: outcome === DecisionOutcome.CONSTRAIN,
    isDenied: outcome === DecisionOutcome.DENY,
    reasons: Object.freeze([...reasons]),
    matchedRule,
    policyHash,
    constraints: constraints ? Object.freeze({ ...constraints }) : null,
    suggestedTransform: suggestedTransform ? Object.freeze({ ...suggestedTransform }) : null,
    timestamp: Date.now(),
  };
}
