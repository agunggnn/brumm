/**
 * @file canonical-json.mjs
 * Deterministic Canonical JSON serialization (RFC 8785 compliant subset)
 * and deep immutability utilities.
 */

import { createHash } from 'node:crypto';

/**
 * Serializes any JavaScript value into deterministic canonical JSON.
 * - Object keys are sorted lexicographically at every recursive depth.
 * - Array element order is strictly preserved.
 * - Floating point / integers formatted deterministically.
 * - Undefined object values are omitted.
 *
 * @param {*} value
 * @returns {string} Deterministic canonical JSON string
 */
export function canonicalizeJson(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      return 'null';
    }
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map(item => {
      const serialized = canonicalizeJson(item);
      return serialized === undefined ? 'null' : serialized;
    });
    return `[${items.join(',')}]`;
  }

  // Object mapping
  const keys = Object.keys(value).sort();
  const pairs = [];

  for (const key of keys) {
    const val = value[key];
    if (val !== undefined && typeof val !== 'function' && typeof val !== 'symbol') {
      const serializedVal = canonicalizeJson(val);
      if (serializedVal !== undefined) {
        pairs.push(`${JSON.stringify(key)}:${serializedVal}`);
      }
    }
  }

  return `{${pairs.join(',')}}`;
}

/**
 * Computes a deterministic SHA-256 hash of any data structure via canonical JSON.
 *
 * @param {*} value
 * @returns {string} 64-character lowercase hex string
 */
export function computeCanonicalSha256(value) {
  const canonicalStr = canonicalizeJson(value);
  return createHash('sha256').update(canonicalStr, 'utf8').digest('hex');
}

/**
 * Recursively freezes an object and all nested objects/arrays to guarantee immutability.
 *
 * @template T
 * @param {T} obj
 * @returns {Readonly<T>}
 */
export function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  Object.freeze(obj);

  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }

  return obj;
}
