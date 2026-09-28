/**
 * @file canonical.mjs
 * Provider-aware canonical resource normalization to prevent path traversal,
 * percent-encoded bypasses, authority substitution, and alias confusion.
 */

import { ResourceCanonicalizationError } from './errors.mjs';

/**
 * Safely decodes percent-encoded sequences while preventing double-encoding bypasses
 * and detecting poison characters (null bytes).
 *
 * @param {string} str
 * @returns {string}
 * @throws {ResourceCanonicalizationError}
 */
export function safePercentDecode(str) {
  let prev = str;
  let decoded = str;

  // Up to 3 passes to catch nested/double-encoding tricks like %252e%252e
  for (let i = 0; i < 3; i++) {
    try {
      decoded = decodeURIComponent(prev);
    } catch {
      throw new ResourceCanonicalizationError(`Malformed percent-encoding in resource: "${str}"`, str);
    }
    if (decoded === prev) break;
    prev = decoded;
  }

  if (decoded.includes('\0')) {
    throw new ResourceCanonicalizationError('Resource identifier contains invalid null byte', str);
  }

  return decoded;
}

/**
 * Normalizes and canonicalizes a resource identifier with provider and authority awareness.
 * Prevents traversal attacks across filesystem boundaries and cloud authority perimeters.
 *
 * @param {string} resource Raw resource identifier, URI, or path
 * @param {object} [options]
 * @param {string} [options.baseDir] Optional root directory constraint for sandboxing
 * @returns {{ uri: string, scheme: string, authority: string|null, path: string, isCanonical: boolean }}
 */
export function canonicalizeResource(resource, options = {}) {
  if (typeof resource !== 'string' || resource.trim().length === 0) {
    throw new TypeError('Resource identifier must be a non-empty string');
  }

  // Reject raw null byte injection early
  if (resource.includes('\0')) {
    throw new ResourceCanonicalizationError('Resource identifier contains invalid null byte', resource);
  }

  // Safe percent-decode to prevent %2e%2e, %2f, %5c bypasses
  const decoded = safePercentDecode(resource.trim());

  // 1. Check for ARN format: arn:partition:service:region:account-id:resource-id
  if (decoded.startsWith('arn:')) {
    const normalizedArn = decoded.replace(/\\/g, '/');
    const arnParts = normalizedArn.split(':');

    // arn:aws:s3:::bucket/key
    if (arnParts[2] === 's3' && arnParts.length >= 6) {
      const s3Target = arnParts.slice(5).join(':');
      const slashIdx = s3Target.indexOf('/');
      let bucket = slashIdx === -1 ? s3Target : s3Target.slice(0, slashIdx);
      let key = slashIdx === -1 ? '' : s3Target.slice(slashIdx + 1);

      // AWS S3 bucket names are strictly lowercase
      bucket = bucket.toLowerCase();

      // Check path traversal inside key
      const keySegments = key.split('/').filter(Boolean);
      const resolvedKey = [];
      for (const seg of keySegments) {
        if (seg === '.') continue;
        if (seg === '..') {
          if (resolvedKey.length > 0) {
            resolvedKey.pop();
          } else {
            throw new ResourceCanonicalizationError(`Path traversal detected in S3 ARN: "${resource}"`, resource);
          }
        } else {
          resolvedKey.push(seg);
        }
      }

      const canonicalKey = resolvedKey.join('/');
      const canonicalUri = `arn:${arnParts[1]}:s3:::${bucket}${canonicalKey ? '/' + canonicalKey : ''}`;

      return {
        uri: canonicalUri,
        scheme: 'arn',
        authority: bucket,
        path: '/' + canonicalKey,
        isCanonical: true,
      };
    }

    return {
      uri: normalizedArn,
      scheme: 'arn',
      authority: null,
      path: normalizedArn.slice(4),
      isCanonical: true,
    };
  }

  // 2. Check for URI schemes with authority: scheme://authority/path
  const uriMatch = decoded.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/]*)(.*)$/);

  if (uriMatch) {
    const scheme = uriMatch[1].toLowerCase();
    const rawAuthority = uriMatch[2];
    const rawPath = uriMatch[3] || '/';

    // Authority must not contain path traversal characters
    if (rawAuthority.includes('..') || rawAuthority.includes('\\')) {
      throw new ResourceCanonicalizationError(
        `Invalid authority in URI: "${rawAuthority}". Traversal characters are forbidden in authority.`,
        resource
      );
    }

    // Cloud providers (S3, GCS, K8s) require lowercase authority
    const authority = rawAuthority.toLowerCase();

    // Normalize path component within the authority
    const normalizedPath = rawPath.replace(/\\/g, '/');
    const segments = normalizedPath.split('/').filter(Boolean);
    const resolved = [];

    for (const seg of segments) {
      if (seg === '.') continue;
      if (seg === '..') {
        if (resolved.length > 0) {
          resolved.pop();
        } else {
          // Traversal attempted to escape authority boundary!
          throw new ResourceCanonicalizationError(
            `Path traversal detected: path escapes authority boundary in "${resource}"`,
            resource
          );
        }
      } else {
        resolved.push(seg);
      }
    }

    const canonicalPath = '/' + resolved.join('/');
    const canonicalUri = `${scheme}://${authority}${canonicalPath === '/' ? '' : canonicalPath}`;

    return {
      uri: canonicalUri,
      scheme,
      authority: authority || null,
      path: canonicalPath,
      isCanonical: true,
    };
  }

  // 3. Filesystem / relative path handling
  let normalized = decoded.replace(/\\/g, '/');
  const isLeadingSlash = normalized.startsWith('/');
  const segments = normalized.split('/').filter(Boolean);
  const resolved = [];
  let traversedAboveRoot = false;

  for (const seg of segments) {
    if (seg === '.') continue;
    if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else {
        traversedAboveRoot = true;
        resolved.push('..');
      }
    } else {
      resolved.push(seg);
    }
  }

  if (traversedAboveRoot && isLeadingSlash) {
    throw new ResourceCanonicalizationError(`Path traversal detected: resource escapes root: "${resource}"`, resource);
  }

  const resolvedPath = (isLeadingSlash ? '/' : '') + resolved.join('/');
  const finalPath = resolvedPath || (isLeadingSlash ? '/' : '.');

  // Enforce baseDir sandbox constraint if specified
  if (options.baseDir) {
    const base = options.baseDir.replace(/\\/g, '/').replace(/\/+$/, '');
    if (!finalPath.startsWith(base + '/') && finalPath !== base) {
      throw new ResourceCanonicalizationError(
        `Resource substitution detected: path "${finalPath}" is outside base directory "${base}"`,
        resource
      );
    }
  }

  return {
    uri: finalPath,
    scheme: 'path',
    authority: null,
    path: finalPath,
    isCanonical: true,
  };
}

/**
 * Checks whether a canonical resource matches a policy resource pattern.
 * Supports glob wildcards:
 *   - '*' matches any characters within a single path segment
 *   - '**' matches across multiple path segments
 *
 * @param {string} canonicalUri
 * @param {string} pattern
 * @returns {boolean}
 */
export function matchResourcePattern(canonicalUri, pattern) {
  if (pattern === '*' || pattern === '**') {
    return true;
  }

  const normPattern = pattern.replace(/\\/g, '/');

  let regexStr = normPattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '§§GLOBSTAR§§')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/§§GLOBSTAR§§/g, '.*');

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(canonicalUri);
}
