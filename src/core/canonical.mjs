/**
 * @file canonical.mjs
 * Canonical resource normalization to prevent path traversal,
 * resource substitution attacks, and alias confusion.
 */

/**
 * Normalizes and canonicalizes a resource identifier.
 * Prevents traversal attacks (e.g. backup-prod/../sensitive-data)
 * and normalizes platform-specific path separators.
 *
 * @param {string} resource Raw resource identifier or path
 * @param {object} [options]
 * @param {string} [options.baseDir] Optional root directory for sandboxing
 * @returns {{ uri: string, scheme: string, path: string, isCanonical: boolean }}
 */
export function canonicalizeResource(resource, options = {}) {
  if (typeof resource !== 'string' || resource.trim().length === 0) {
    throw new TypeError('Resource identifier must be a non-empty string');
  }

  // Reject null-byte injection
  if (resource.includes('\0')) {
    throw new Error('Resource identifier contains invalid null byte (potential poison attack)');
  }

  const raw = resource.trim();

  // Check for URI scheme (e.g. s3://, file://, k8s://, mem://)
  const schemeMatch = raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/);
  let scheme = 'path';
  let pathPart = raw;

  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    pathPart = schemeMatch[2];
  }

  // Normalize all backslashes to forward slashes
  let normalized = pathPart.replace(/\\/g, '/');

  // Collapse multiple consecutive slashes except when leading
  const isLeadingSlash = normalized.startsWith('/');
  const segments = normalized.split('/').filter(Boolean);

  // Resolve '.' and '..' segments deterministically
  const resolved = [];
  let traversedAboveRoot = false;

  for (const seg of segments) {
    if (seg === '.') {
      continue;
    }
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
    throw new Error(`Path traversal detected: resource escapes root: "${resource}"`);
  }

  const resolvedPath = (isLeadingSlash ? '/' : '') + resolved.join('/');
  const finalPath = resolvedPath || (isLeadingSlash ? '/' : '.');

  let canonicalUri = scheme === 'path' ? finalPath : `${scheme}://${finalPath}`;

  // If baseDir sandbox constraint is given, ensure the path stays inside baseDir
  if (options.baseDir && scheme === 'path') {
    const base = options.baseDir.replace(/\\/g, '/').replace(/\/+$/, '');
    if (!finalPath.startsWith(base + '/') && finalPath !== base) {
      throw new Error(`Resource substitution detected: path "${finalPath}" is outside base directory "${base}"`);
    }
  }

  return {
    uri: canonicalUri,
    scheme,
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

  // Normalize pattern slashes
  const normPattern = pattern.replace(/\\/g, '/');

  // Convert glob pattern to regular expression
  // Escape regex special chars except * and ?
  let regexStr = normPattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '§§GLOBSTAR§§')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/§§GLOBSTAR§§/g, '.*');

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(canonicalUri);
}
