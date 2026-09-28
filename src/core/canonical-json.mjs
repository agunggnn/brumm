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
 * Recursively freezes an object and all nested objects/arrays/symbols to guarantee immutability.
 * Traverses both string and symbol own properties and handles circular references safely.
 *
 * @template T
 * @param {T} obj
 * @param {Set<any>} [seen]
 * @returns {Readonly<T>}
 */
export function deepFreeze(obj, seen = new Set()) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (seen.has(obj)) {
    return obj;
  }
  seen.add(obj);

  Object.freeze(obj);

  for (const key of Reflect.ownKeys(obj)) {
    let val;
    try {
      val = obj[key];
    } catch {
      continue;
    }
    if (val !== null && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val, seen);
    }
  }

  return obj;
}

/**
 * Recursively verifies that an object and all nested objects/arrays/symbols are frozen.
 * Traverses both string and symbol own properties and handles circular references safely.
 *
 * @param {any} obj
 * @param {Set<any>} [seen]
 * @returns {boolean}
 */
export function isDeepFrozen(obj, seen = new Set()) {
  if (obj === null || typeof obj !== 'object') {
    return true;
  }

  if (seen.has(obj)) {
    return true;
  }

  if (!Object.isFrozen(obj)) {
    return false;
  }

  seen.add(obj);

  for (const key of Reflect.ownKeys(obj)) {
    let val;
    try {
      val = obj[key];
    } catch {
      return false;
    }
    if (val !== null && typeof val === 'object') {
      if (!isDeepFrozen(val, seen)) {
        return false;
      }
    }
  }

  return true;
}
