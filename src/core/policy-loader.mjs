/**
 * @file policy-loader.mjs
 * Policy schema validation, compiler, loader, and canonical SHA-256 hasher.
 * Enforces deep immutability and rejects unknown fields or invalid effects at compile time.
 */

import { readFileSync } from 'node:fs';
import { computeCanonicalSha256, deepFreeze } from './canonical-json.mjs';
export { computeCanonicalSha256 as computePolicyHash };

/**
 * Symbol brand applied exclusively to authentic compiled policies.
 */
export const COMPILED_POLICY_BRAND = Symbol.for('brumm.compiled.policy');
import {
  DecisionOutcome,
  ValidDefaultEffects,
  ValidEffects,
  parseByteSize,
} from './decision.mjs';
import { PolicyValidationError } from './errors.mjs';

const ALLOWED_TOP_LEVEL_FIELDS = new Set([
  'name',
  'version',
  'defaultEffect',
  'rules',
  'metadata',
  'description',
]);

const ALLOWED_RULE_FIELDS = new Set([
  'id',
  'description',
  'effect',
  'agent',
  'action',
  'resource',
  'environment',
  'reasons',
  'reason',
  'constraints',
  'isCriticalProtection',
  'critical',
]);

const ALLOWED_CONSTRAINT_FIELDS = new Set([
  'max_size',
  'absolute_max_size',
  'autonomous_max_size',
  'approval_above',
  'require_approval_above',
  'max_objects',
  'absolute_max_objects',
  'approval_above_objects',
  'require_approval_above_objects',
  'require_snapshot',
  'dry_run_only',
]);

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Checks that a property key does not cause prototype pollution and is unique in mapping.
 *
 * @param {object} obj
 * @param {string} key
 * @throws {PolicyValidationError}
 */
function checkSafeAndUniqueKey(obj, key) {
  if (FORBIDDEN_KEYS.has(key)) {
    throw new PolicyValidationError(
      `Security error: YAML mapping contains forbidden prototype-polluting key "${key}"`,
      key
    );
  }
  if (Object.prototype.hasOwnProperty.call(obj, key)) {
    throw new PolicyValidationError(
      `Duplicate YAML key detected in mapping: "${key}"`,
      key
    );
  }
}

/**
 * Strictly parses and validates a non-negative integer object count limit.
 *
 * @param {any} val
 * @param {string} fieldName
 * @param {string} ruleId
 * @returns {number|null}
 */
function parseObjectLimit(val, fieldName, ruleId) {
  if (val === undefined || val === null) return null;
  if (typeof val === 'number') {
    if (!Number.isSafeInteger(val) || val < 0) {
      throw new PolicyValidationError(
        `Invalid value for constraint "${fieldName}" in rule "${ruleId}": must be a safe non-negative integer, got ${val}`,
        fieldName,
        ruleId
      );
    }
    return val;
  }
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!/^[0-9]+$/.test(trimmed)) {
      throw new PolicyValidationError(
        `Invalid value for constraint "${fieldName}" in rule "${ruleId}": expected non-negative integer string, got "${val}"`,
        fieldName,
        ruleId
      );
    }
    const num = Number(trimmed);
    if (!Number.isSafeInteger(num) || num < 0) {
      throw new PolicyValidationError(
        `Invalid value for constraint "${fieldName}" in rule "${ruleId}": integer out of safe range`,
        fieldName,
        ruleId
      );
    }
    return num;
  }
  throw new PolicyValidationError(
    `Invalid value for constraint "${fieldName}" in rule "${ruleId}": expected integer, got ${typeof val}`,
    fieldName,
    ruleId
  );
}

/**
 * Validates the raw policy schema strictly before compilation.
 * Rejects unknown fields, invalid types, duplicate rule IDs, and malformed effects.
 *
 * @param {object} rawPolicy
 * @throws {PolicyValidationError}
 */
export function validatePolicySchema(rawPolicy) {
  if (!rawPolicy || typeof rawPolicy !== 'object' || Array.isArray(rawPolicy)) {
    throw new PolicyValidationError('Policy definition must be a non-null object');
  }

  // Check top-level unknown fields and prototype pollution
  for (const key of Object.keys(rawPolicy)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new PolicyValidationError(`Security error: Policy contains forbidden prototype key "${key}"`, key);
    }
    if (!ALLOWED_TOP_LEVEL_FIELDS.has(key)) {
      throw new PolicyValidationError(`Unknown top-level field in policy: "${key}"`, key);
    }
  }

  // Validate defaultEffect if present
  if (rawPolicy.defaultEffect !== undefined) {
    if (typeof rawPolicy.defaultEffect !== 'string') {
      throw new PolicyValidationError('Field "defaultEffect" must be a string', 'defaultEffect');
    }
    const def = rawPolicy.defaultEffect.toUpperCase();
    if (!ValidDefaultEffects.includes(def)) {
      throw new PolicyValidationError(
        `Invalid defaultEffect: "${rawPolicy.defaultEffect}". Must be one of: ${ValidDefaultEffects.join(', ')}`,
        'defaultEffect'
      );
    }
  }

  // Validate rules
  if (rawPolicy.rules !== undefined) {
    if (!Array.isArray(rawPolicy.rules)) {
      throw new PolicyValidationError('Field "rules" must be an array', 'rules');
    }

    const seenRuleIds = new Set();

    for (let i = 0; i < rawPolicy.rules.length; i++) {
      const rule = rawPolicy.rules[i];
      const ruleId = rule && rule.id ? rule.id : `rule[${i}]`;

      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
        throw new PolicyValidationError(`Rule at index ${i} must be an object`, 'rules', ruleId);
      }

      // Check duplicate rule IDs
      if (rule.id !== undefined && rule.id !== null) {
        if (typeof rule.id !== 'string' || rule.id.trim().length === 0) {
          throw new PolicyValidationError(`Rule id at index ${i} must be a non-empty string`, 'id', ruleId);
        }
        const trimmedId = rule.id.trim();
        if (seenRuleIds.has(trimmedId)) {
          throw new PolicyValidationError(
            `Duplicate rule ID detected: "${trimmedId}". Rule IDs must be unique across the policy.`,
            'id',
            trimmedId
          );
        }
        seenRuleIds.add(trimmedId);
      }

      // Check rule-level unknown fields and prototype pollution
      for (const key of Object.keys(rule)) {
        if (FORBIDDEN_KEYS.has(key)) {
          throw new PolicyValidationError(`Security error: Rule contains forbidden prototype key "${key}"`, key, ruleId);
        }
        if (!ALLOWED_RULE_FIELDS.has(key)) {
          throw new PolicyValidationError(
            `Unknown field "${key}" in rule "${ruleId}". Typo protection active.`,
            key,
            ruleId
          );
        }
      }

      // Validate effect
      let eff = 'DENY';
      if (rule.effect !== undefined) {
        if (typeof rule.effect !== 'string') {
          throw new PolicyValidationError(`Field "effect" in rule "${ruleId}" must be a string`, 'effect', ruleId);
        }
        eff = rule.effect.toUpperCase();
        if (!ValidEffects.includes(eff)) {
          throw new PolicyValidationError(
            `Invalid effect "${rule.effect}" in rule "${ruleId}". Must be one of: ${ValidEffects.join(', ')}`,
            'effect',
            ruleId
          );
        }
      }

      // Require explicit agent and resource on ALLOW and CONSTRAIN rules
      if (eff === DecisionOutcome.ALLOW || eff === DecisionOutcome.CONSTRAIN) {
        if (rule.agent === undefined || rule.agent === null || typeof rule.agent !== 'string' || rule.agent.trim().length === 0) {
          throw new PolicyValidationError(
            `Rule "${ruleId}" with effect "${eff}" must explicitly declare an "agent" pattern (wildcard "*" must be explicit)`,
            'agent',
            ruleId
          );
        }
        if (rule.resource === undefined || rule.resource === null || typeof rule.resource !== 'string' || rule.resource.trim().length === 0) {
          throw new PolicyValidationError(
            `Rule "${ruleId}" with effect "${eff}" must explicitly declare a "resource" pattern (wildcard "*" must be explicit)`,
            'resource',
            ruleId
          );
        }
      }

      // Reject contradictory critical: true with permissive effect
      const isCritical = Boolean(rule.isCriticalProtection || rule.critical);
      if (isCritical && (eff === DecisionOutcome.ALLOW || eff === DecisionOutcome.CONSTRAIN)) {
        throw new PolicyValidationError(
          `Contradictory rule configuration in rule "${ruleId}": cannot combine critical asset protection (critical: true) with permissive effect "${eff}". Critical assets must specify effect DENY.`,
          'critical',
          ruleId
        );
      }

      // Validate constraints if present
      if (rule.constraints !== undefined) {
        if (typeof rule.constraints !== 'object' || Array.isArray(rule.constraints) || rule.constraints === null) {
          throw new PolicyValidationError(
            `Field "constraints" in rule "${ruleId}" must be an object`,
            'constraints',
            ruleId
          );
        }

        const SIZE_FIELDS = new Set([
          'max_size',
          'absolute_max_size',
          'autonomous_max_size',
          'approval_above',
          'require_approval_above',
        ]);

        const OBJECT_FIELDS = new Set([
          'max_objects',
          'absolute_max_objects',
          'approval_above_objects',
          'require_approval_above_objects',
        ]);

        const BOOLEAN_FIELDS = new Set([
          'require_snapshot',
          'dry_run_only',
        ]);

        for (const cKey of Object.keys(rule.constraints)) {
          if (FORBIDDEN_KEYS.has(cKey)) {
            throw new PolicyValidationError(`Security error: Constraint contains forbidden prototype key "${cKey}"`, cKey, ruleId);
          }
          if (!ALLOWED_CONSTRAINT_FIELDS.has(cKey)) {
            throw new PolicyValidationError(
              `Unknown constraint "${cKey}" in rule "${ruleId}".`,
              cKey,
              ruleId
            );
          }

          const val = rule.constraints[cKey];

          if (SIZE_FIELDS.has(cKey)) {
            try {
              parseByteSize(val);
            } catch (err) {
              throw new PolicyValidationError(
                `Invalid byte size for constraint "${cKey}" in rule "${ruleId}": ${err.message}`,
                cKey,
                ruleId
              );
            }
          } else if (OBJECT_FIELDS.has(cKey)) {
            let isValid = false;
            if (typeof val === 'number') {
              isValid = Number.isSafeInteger(val) && val >= 0;
            } else if (typeof val === 'string') {
              const trimmed = val.trim();
              if (/^[0-9]+$/.test(trimmed)) {
                const parsed = Number(trimmed);
                isValid = Number.isSafeInteger(parsed) && parsed >= 0;
              }
            }
            if (!isValid) {
              throw new PolicyValidationError(
                `Invalid value for object count constraint "${cKey}" in rule "${ruleId}": expected a non-negative integer, got ${JSON.stringify(val)}`,
                cKey,
                ruleId
              );
            }
          } else if (BOOLEAN_FIELDS.has(cKey)) {
            if (typeof val !== 'boolean') {
              throw new PolicyValidationError(
                `Constraint "${cKey}" in rule "${ruleId}" must be a boolean, got ${typeof val}`,
                cKey,
                ruleId
              );
            }
          }
        }
      }
    }
  }
}

/**
 * Strips comments from a YAML line while preserving '#' inside single or double quotes.
 *
 * @param {string} line
 * @returns {string}
 */
function stripYamlComment(line) {
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let escapeNext = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (escapeNext) {
      escapeNext = false;
      continue;
    }

    if (char === '\\' && inDoubleQuote) {
      escapeNext = true;
      continue;
    }

    if (char === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      continue;
    }

    if (char === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }

    // A comment starts with # only when outside quotes
    if (char === '#' && !inSingleQuote && !inDoubleQuote) {
      if (i === 0 || /\s/.test(line[i - 1])) {
        return line.slice(0, i);
      }
    }
  }
  return line;
}

/**
 * Lightweight, zero-dependency YAML parser for policy configuration.
 * Hardened against duplicate keys, prototype pollution, tab indentation, and comment truncation.
 *
 * @param {string} text Raw YAML content
 * @returns {object} Parsed JavaScript object
 */
export function parseYamlSubset(text) {
  if (typeof text !== 'string') {
    throw new PolicyValidationError('YAML content must be a string');
  }

  const rawLines = text.split(/\r?\n/);

  // Reject leading tabs for indentation in YAML
  for (let i = 0; i < rawLines.length; i++) {
    const rawLine = rawLines[i];
    const match = rawLine.match(/^\s*/);
    if (match && match[0].includes('\t')) {
      throw new PolicyValidationError(
        `YAML parsing error: Tabs are not allowed for indentation at line ${i + 1}`,
        'yaml'
      );
    }
  }

  const lines = rawLines
    .map(line => stripYamlComment(line))
    .filter(line => line.trim().length > 0);

  let lineIdx = 0;

  function parseBlock(currentIndent) {
    let result = null;
    let isArray = false;

    while (lineIdx < lines.length) {
      const line = lines[lineIdx];
      const indent = line.search(/\S/);

      if (indent < currentIndent) {
        break;
      }

      const trimmed = line.trim();

      if (trimmed.startsWith('- ')) {
        if (result === null) {
          result = [];
          isArray = true;
        } else if (!isArray) {
          break;
        }

        const itemContent = trimmed.slice(2).trim();
        lineIdx++;

        if (itemContent.length === 0) {
          result.push(parseBlock(indent + 2));
        } else if (itemContent.includes(':')) {
          const firstColon = itemContent.indexOf(':');
          const k = itemContent.slice(0, firstColon).trim();
          const v = itemContent.slice(firstColon + 1).trim();

          const obj = {};
          checkSafeAndUniqueKey(obj, k);
          if (v.length > 0) {
            obj[k] = parseScalar(v);
          } else {
            obj[k] = parseBlock(indent + 4);
          }

          while (lineIdx < lines.length) {
            const nextLine = lines[lineIdx];
            const nextIndent = nextLine.search(/\S/);
            const nextTrimmed = nextLine.trim();

            if (nextIndent <= indent || nextTrimmed.startsWith('- ')) {
              break;
            }

            const colonIdx = nextTrimmed.indexOf(':');
            if (colonIdx === -1) {
              lineIdx++;
              continue;
            }

            const subKey = nextTrimmed.slice(0, colonIdx).trim();
            const subVal = nextTrimmed.slice(colonIdx + 1).trim();
            lineIdx++;

            checkSafeAndUniqueKey(obj, subKey);
            if (subVal.length > 0) {
              obj[subKey] = parseScalar(subVal);
            } else {
              obj[subKey] = parseBlock(nextIndent + 2);
            }
          }

          result.push(obj);
        } else {
          result.push(parseScalar(itemContent));
        }
        continue;
      }

      const colonIdx = trimmed.indexOf(':');
      if (colonIdx !== -1) {
        if (result === null) {
          result = {};
          isArray = false;
        } else if (isArray) {
          break;
        }

        const key = trimmed.slice(0, colonIdx).trim();
        const rawVal = trimmed.slice(colonIdx + 1).trim();
        lineIdx++;

        checkSafeAndUniqueKey(result, key);
        if (rawVal.length > 0) {
          result[key] = parseScalar(rawVal);
        } else {
          result[key] = parseBlock(indent + 2);
        }
        continue;
      }

      lineIdx++;
    }

    return result;
  }

  function parseScalar(val) {
    if (val === 'true' || val === 'TRUE') return true;
    if (val === 'false' || val === 'FALSE') return false;
    if (val === 'null' || val === '~') return null;

    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      return val.slice(1, -1);
    }

    if (/^-?[0-9]+(?:\.[0-9]+)?$/.test(val)) {
      return Number(val);
    }

    if (val.startsWith('[') && val.endsWith(']')) {
      return val.slice(1, -1).split(',').map(s => parseScalar(s.trim())).filter(s => s !== '');
    }

    return val;
  }

  return parseBlock(0) || {};
}

/**
 * Validates and compiles a policy object into a deeply immutable, verified representation.
 *
 * @param {object} rawPolicy
 * @returns {object} Compiled immutable policy
 * @throws {PolicyValidationError} If schema or values are invalid
 */
export function compilePolicy(rawPolicy) {
  // 1. Strict schema validation
  validatePolicySchema(rawPolicy);

  const name = typeof rawPolicy.name === 'string' ? rawPolicy.name : 'unnamed-policy';
  const version = typeof rawPolicy.version === 'string' ? rawPolicy.version : '1.0';
  const defaultEffect = (rawPolicy.defaultEffect || 'DENY').toUpperCase();

  const rawRules = Array.isArray(rawPolicy.rules) ? rawPolicy.rules : [];
  const compiledRules = [];

  for (let i = 0; i < rawRules.length; i++) {
    const rule = rawRules[i];
    if (!rule || typeof rule !== 'object') continue;

    const id = rule.id || `rule-${i + 1}`;
    const effect = (rule.effect || 'DENY').toUpperCase();
    const agentPattern = rule.agent || '*';
    const actionPattern = (rule.action || '*').toLowerCase();
    const resourcePattern = rule.resource || '*';
    const environmentPattern = rule.environment ? rule.environment.toLowerCase() : '*';

    const reasons = Array.isArray(rule.reasons)
      ? rule.reasons.map(String)
      : (rule.reason ? [String(rule.reason)] : []);

    const rawConstraints = rule.constraints || {};

    // Parse size limits (strictly preserve 0)
    const rawMaxSize = rawConstraints.absolute_max_size !== undefined
      ? rawConstraints.absolute_max_size
      : rawConstraints.max_size;
    const rawApprovalAbove = rawConstraints.require_approval_above !== undefined
      ? rawConstraints.require_approval_above
      : (rawConstraints.approval_above !== undefined ? rawConstraints.approval_above : rawConstraints.autonomous_max_size);

    const absoluteMaxSize = (rawMaxSize !== undefined && rawMaxSize !== null)
      ? parseByteSize(rawMaxSize)
      : null;
    const requireApprovalAbove = (rawApprovalAbove !== undefined && rawApprovalAbove !== null)
      ? parseByteSize(rawApprovalAbove)
      : null;

    if (absoluteMaxSize !== null && requireApprovalAbove !== null && requireApprovalAbove > absoluteMaxSize) {
      throw new PolicyValidationError(
        `In rule "${id}": require_approval_above (${requireApprovalAbove}B) cannot be greater than absolute_max_size (${absoluteMaxSize}B)`,
        'constraints',
        id
      );
    }

    // Parse object count limits (strictly preserve 0)
    const rawMaxObjects = rawConstraints.absolute_max_objects !== undefined
      ? rawConstraints.absolute_max_objects
      : rawConstraints.max_objects;
    const rawApprovalAboveObjects = rawConstraints.require_approval_above_objects !== undefined
      ? rawConstraints.require_approval_above_objects
      : rawConstraints.approval_above_objects;

    const absoluteMaxObjects = (rawMaxObjects !== undefined && rawMaxObjects !== null)
      ? parseObjectLimit(rawMaxObjects, 'max_objects', id)
      : null;

    const requireApprovalAboveObjects = (rawApprovalAboveObjects !== undefined && rawApprovalAboveObjects !== null)
      ? parseObjectLimit(rawApprovalAboveObjects, 'approval_above_objects', id)
      : null;

    if (absoluteMaxObjects !== null && requireApprovalAboveObjects !== null && requireApprovalAboveObjects > absoluteMaxObjects) {
      throw new PolicyValidationError(
        `In rule "${id}": approval_above_objects cannot be greater than max_objects`,
        'constraints',
        id
      );
    }

    const constraints = {
      absoluteMaxSize,
      requireApprovalAbove,
      absoluteMaxObjects,
      requireApprovalAboveObjects,
      requireSnapshot: Boolean(rawConstraints.require_snapshot),
      dryRunOnly: Boolean(rawConstraints.dry_run_only),
    };

    compiledRules.push({
      id,
      effect,
      agentPattern,
      actionPattern,
      resourcePattern,
      environmentPattern,
      reasons,
      constraints,
      isCriticalProtection: Boolean(rule.isCriticalProtection || rule.critical),
    });
  }

  // 2. Canonical JSON hashing of the normalized policy structure
  const normalizedStructure = {
    name,
    version,
    defaultEffect,
    rules: compiledRules.map(r => ({
      id: r.id,
      effect: r.effect,
      agent: r.agentPattern,
      action: r.actionPattern,
      resource: r.resourcePattern,
      environment: r.environmentPattern,
      reasons: r.reasons,
      constraints: r.constraints,
      critical: r.isCriticalProtection,
    })),
  };

  const hash = computeCanonicalSha256(normalizedStructure);

  const compiled = {
    name,
    version,
    defaultEffect,
    rules: compiledRules,
    hash,
    [COMPILED_POLICY_BRAND]: true,
  };

  // 3. Deep freeze to prevent any post-compilation mutation
  return deepFreeze(compiled);
}

/**
 * Strictly verifies whether an object is an authentic, deeply immutable, compiled policy.
 * Validates brand identity, immutability, structure, and verifies that the canonical SHA-256
 * digest matches the compiled policy structure.
 *
 * @param {any} policy
 * @returns {boolean}
 */
export function isCompiledPolicy(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    return false;
  }

  if (policy[COMPILED_POLICY_BRAND] !== true) {
    return false;
  }

  if (!Object.isFrozen(policy)) {
    return false;
  }

  if (typeof policy.hash !== 'string' || !/^[0-9a-f]{64}$/.test(policy.hash)) {
    return false;
  }

  if (!Array.isArray(policy.rules)) {
    return false;
  }

  // Cryptographic integrity verification: recompute canonical SHA-256
  try {
    const normalizedStructure = {
      name: typeof policy.name === 'string' ? policy.name : 'unnamed-policy',
      version: typeof policy.version === 'string' ? policy.version : '1.0',
      defaultEffect: (policy.defaultEffect || 'DENY').toUpperCase(),
      rules: policy.rules.map(r => ({
        id: r.id,
        effect: r.effect,
        agent: r.agentPattern,
        action: r.actionPattern,
        resource: r.resourcePattern,
        environment: r.environmentPattern,
        reasons: r.reasons,
        constraints: r.constraints,
        critical: Boolean(r.isCriticalProtection),
      })),
    };
    const expectedHash = computeCanonicalSha256(normalizedStructure);
    if (expectedHash !== policy.hash) {
      return false;
    }
  } catch {
    return false;
  }

  return true;
}

/**
 * Loads, validates, and compiles a policy from a file path (JSON or YAML).
 *
 * @param {string} filePath
 * @returns {object} Deeply immutable compiled policy
 */
export function loadPolicyFile(filePath) {
  const content = readFileSync(filePath, 'utf8');

  let rawPolicy;
  if (filePath.endsWith('.json')) {
    rawPolicy = JSON.parse(content);
  } else {
    try {
      rawPolicy = parseYamlSubset(content);
    } catch {
      rawPolicy = JSON.parse(content);
    }
  }

  return compilePolicy(rawPolicy);
}
