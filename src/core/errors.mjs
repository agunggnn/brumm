/**
 * @file errors.mjs
 * Custom error types for Brumm policy validation, capability governance, and execution enforcement.
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

export class CapabilitySecurityError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'CAPABILITY_ERROR') {
    super(message);
    this.name = 'CapabilitySecurityError';
    this.code = code;
  }
}

export class ExecutionSecurityError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = 'EXECUTION_BLOCKED') {
    super(message);
    this.name = 'ExecutionSecurityError';
    this.code = code;
  }
}
