/**
 * @file decision.mjs
 * Policy decision outcomes, rule effects, precedence definitions, and size parsers.
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
 * Valid rule effects supported by the policy engine.
 */
export const ValidEffects = Object.freeze([
  DecisionOutcome.ALLOW,
  DecisionOutcome.DENY,
  DecisionOutcome.CONSTRAIN,
  DecisionOutcome.ESCALATE,
]);

/**
 * Valid default effects for policy level.
 */
export const ValidDefaultEffects = Object.freeze([
  DecisionOutcome.ALLOW,
  DecisionOutcome.DENY,
]);

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
 * SI (Decimal) byte multipliers (10^N)
 */
const DECIMAL_MULTIPLIERS = {
  B: 1,
  KB: 1000,
  MB: 1000 ** 2,
  GB: 1000 ** 3,
  TB: 1000 ** 4,
};

/**
 * IEC (Binary) byte multipliers (2^N)
 */
const BINARY_MULTIPLIERS = {
  KIB: 1024,
  MIB: 1024 ** 2,
  GIB: 1024 ** 3,
  TIB: 1024 ** 4,
};

/**
 * Parses a byte size string into numeric bytes with strict validation.
 * Distinguishes decimal (GB = 1e9) from binary (GiB = 2^30) units.
 * Throws TypeError on invalid syntax or unrecognized units.
 *
 * @param {string|number} sizeStr e.g. "50GB", "50GiB", "500MB", "1024"
 * @returns {number} Integer number of bytes
 * @throws {TypeError} If format or unit is invalid
 */
export function parseByteSize(sizeStr) {
  if (typeof sizeStr === 'number') {
    if (!Number.isFinite(sizeStr) || sizeStr < 0) {
      throw new TypeError(`Invalid byte size number: ${sizeStr}. Must be a finite non-negative number.`);
    }
    return Math.floor(sizeStr);
  }

  if (typeof sizeStr !== 'string' || sizeStr.trim().length === 0) {
    throw new TypeError('Byte size must be a non-empty string or positive number');
  }

  const trimmed = sizeStr.trim().toUpperCase();
  const match = trimmed.match(/^([0-9]+(?:\.[0-9]+)?)\s*([A-Z]*)$/);

  if (!match) {
    throw new TypeError(`Invalid byte size format: "${sizeStr}". Expected format like "50GB", "50GiB", "1024"`);
  }

  const val = parseFloat(match[1]);
  const unit = match[2];

  if (!unit || unit === 'B') {
    return Math.floor(val);
  }

  if (unit in BINARY_MULTIPLIERS) {
    return Math.floor(val * BINARY_MULTIPLIERS[unit]);
  }

  if (unit in DECIMAL_MULTIPLIERS) {
    return Math.floor(val * DECIMAL_MULTIPLIERS[unit]);
  }

  throw new TypeError(
    `Invalid byte size unit "${unit}" in "${sizeStr}". Supported units: B, KB, MB, GB, TB (decimal) or KiB, MiB, GiB, TiB (binary).`
  );
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
