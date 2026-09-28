/**
 * @file policy-loader.mjs
 * Policy parser, validator, and SHA-256 canonical hash generator.
 * Zero-dependency: natively supports JSON and standard YAML policies.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseByteSize } from './decision.mjs';

/**
 * Lightweight, zero-dependency YAML parser for policy configuration.
 * Handles mappings, sequences, quoted/unquoted strings, numbers, and booleans.
 *
 * @param {string} text Raw YAML content
 * @returns {object} Parsed JavaScript object
 */
export function parseYamlSubset(text) {
  const lines = text
    .split(/\r?\n/)
    .map(line => {
      // Strip comments that are not within quotes
      const commentIdx = line.search(/(?<!['"])\s*#.*$/);
      return commentIdx !== -1 ? line.slice(0, commentIdx) : line;
    })
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

      // Check for array item
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
          // Nested block under array item
          result.push(parseBlock(indent + 2));
        } else if (itemContent.includes(':')) {
          // Object inline start, e.g. "- id: foo"
          const firstColon = itemContent.indexOf(':');
          const k = itemContent.slice(0, firstColon).trim();
          const v = itemContent.slice(firstColon + 1).trim();

          const obj = {};
          if (v.length > 0) {
            obj[k] = parseScalar(v);
          } else {
            obj[k] = parseBlock(indent + 4);
          }

          // Read subsequent keys belonging to this array item
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

      // Check for object key-value
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

    // Quoted strings
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      return val.slice(1, -1);
    }

    // Number
    if (/^-?[0-9]+(?:\.[0-9]+)?$/.test(val)) {
      return Number(val);
    }

    // Bracketed array, e.g. [a, b, c]
    if (val.startsWith('[') && val.endsWith(']')) {
      return val.slice(1, -1).split(',').map(s => parseScalar(s.trim())).filter(s => s !== '');
    }

    return val;
  }

  return parseBlock(0) || {};
}

/**
 * Computes a deterministic SHA-256 canonical hash of a policy object.
 *
 * @param {object} policy
 * @returns {string} SHA-256 hex string
 */
export function computePolicyHash(policy) {
  const canonicalString = JSON.stringify(policy, Object.keys(policy).sort());
  return createHash('sha256').update(canonicalString).digest('hex');
}

/**
 * Validates and compiles a policy object into an executable policy representation.
 *
 * @param {object} rawPolicy
 * @returns {object} Compiled policy object
 */
export function compilePolicy(rawPolicy) {
  if (!rawPolicy || typeof rawPolicy !== 'object') {
    throw new TypeError('Policy definition must be a non-null object');
  }

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

    // Parse reasons
    const reasons = Array.isArray(rule.reasons)
      ? rule.reasons.map(String)
      : (rule.reason ? [String(rule.reason)] : []);

    // Parse constraints
    const rawConstraints = rule.constraints || {};
    const constraints = {
      maxBytes: rawConstraints.max_size ? parseByteSize(rawConstraints.max_size) : null,
      maxObjects: typeof rawConstraints.max_objects === 'number' ? rawConstraints.max_objects : null,
      requireSnapshot: Boolean(rawConstraints.require_snapshot),
      requireApprovalAbove: rawConstraints.require_approval_above
        ? parseByteSize(rawConstraints.require_approval_above)
        : null,
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

  const compiled = {
    name,
    version,
    defaultEffect,
    rules: compiledRules,
    hash: computePolicyHash(rawPolicy),
  };

  return Object.freeze(compiled);
}

/**
 * Loads and compiles a policy from a file path (JSON or YAML).
 *
 * @param {string} filePath Absolute or relative path to policy file
 * @returns {object} Compiled policy
 */
export function loadPolicyFile(filePath) {
  const content = readFileSync(filePath, 'utf8');

  let rawPolicy;
  if (filePath.endsWith('.json')) {
    rawPolicy = JSON.parse(content);
  } else {
    // Assume YAML (.yaml, .yml)
    try {
      rawPolicy = parseYamlSubset(content);
    } catch {
      // Fallback to JSON in case it was JSON in disguise
      rawPolicy = JSON.parse(content);
    }
  }

  return compilePolicy(rawPolicy);
}
