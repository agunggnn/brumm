/**
 * @file errors.mjs
 * Custom error types for Brumm policy validation and evaluation.
 */

export class PolicyValidationError extends Error {
  /**
   * @param {string} message
   * @param {string} [field]
   * @param {string} [ruleId]
   */
  constructor(message, field = null, ruleId = null) {
    super(message);
    this.name = 'PolicyValidationError';
    this.field = field;
    this.ruleId = ruleId;
  }
}

export class ResourceCanonicalizationError extends Error {
  /**
   * @param {string} message
   * @param {string} [resource]
   */
  constructor(message, resource = null) {
    super(message);
    this.name = 'ResourceCanonicalizationError';
    this.resource = resource;
  }
}
