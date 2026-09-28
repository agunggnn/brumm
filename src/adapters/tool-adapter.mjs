/**
 * @file tool-adapter.mjs
 * Execution Boundary & Tool Guard Adapter.
 * Enforces dynamic capability verification, atomic nonce consumption,
 * and parameter-to-resource binding directly before invocation of underlying tools.
 */

import { canonicalizeResource, matchResourcePattern } from '../core/canonical.mjs';
import {
  issueCapability,
  verifyCapability,
} from '../core/capability.mjs';
import { parseByteSize } from '../core/decision.mjs';
import { ExecutionSecurityError } from '../core/errors.mjs';
import { normalizeActionRequest } from '../core/identity.mjs';

/**
 * Creates an Execution Guard that wraps underlying tools and enforces
 * capability verification at the physical execution boundary.
 *
 * @param {object} options
 * @param {object} options.guard Brumm guard instance created with createGuard()
 * @param {string} [options.signingKey] Optional capability signing key
 * @returns {object} Execution Guard
 */
export function createExecutionGuard(options = {}) {
  const { guard, signingKey } = options;

  if (!guard || typeof guard.evaluate !== 'function') {
    throw new TypeError('ExecutionGuard requires a valid Brumm guard instance');
  }

  return {
    /**
     * Protects an underlying tool executor function.
     * Prevents any direct invocation unless a valid, signed, unconsumed capability is presented,
     * and strictly binds the caller's actual parameters to the authorized capability resource.
     *
     * @param {string} toolName
     * @param {Function} rawExecutor The actual tool function (e.g. AWS SDK call, fs.rm, kubectl)
     * @returns {Function} Protected executor
     */
    protect(toolName, rawExecutor) {
      if (typeof toolName !== 'string' || toolName.trim().length === 0) {
        throw new TypeError('Tool name must be a non-empty string');
      }
      if (typeof rawExecutor !== 'function') {
        throw new TypeError(`Executor for tool "${toolName}" must be a function`);
      }

      const normalizedTool = toolName.trim().toLowerCase();

      return async function protectedExecutor(params = {}, securityContext = {}) {
        const { capability, request, context } = securityContext;

        if (!capability) {
          throw new ExecutionSecurityError(
            `Direct execution blocked for tool "${toolName}": missing Brumm dynamic capability lease`,
            'MISSING_CAPABILITY'
          );
        }

        // 1. Tool-to-Capability Action Binding:
        // Enforce physical execution invariant: toolName === capability.action === verifiedRequest.action
        if (normalizedTool !== capability.action) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": tool action ("${normalizedTool}") does not match authorized capability action ("${capability.action}")`,
            'TOOL_ACTION_MISMATCH'
          );
        }

        if (request && typeof request === 'object' && request.action !== undefined) {
          if (typeof request.action !== 'string' || request.action.trim().toLowerCase() !== normalizedTool) {
            throw new ExecutionSecurityError(
              `Execution blocked for tool "${toolName}": request action ("${request.action}") does not match tool action ("${normalizedTool}")`,
              'TOOL_ACTION_MISMATCH'
            );
          }
        }

        // 2. Parameter Substitution Defense:
        // Ensure that all candidate resource parameters present in caller's payload match the authorized capability resource
        const CANDIDATE_RESOURCE_KEYS = [
          'resource',
          'target',
          'path',
          'destination',
          'dest',
          'file',
          'filePath',
          'filepath',
          'uri',
          'url',
          'source',
          'src',
        ];

        const authorizedResource = capability.resource;

        const checkResourceTarget = (paramKey, targetVal) => {
          if (typeof targetVal === 'string' && targetVal.trim().length > 0) {
            let canonicalParam;
            try {
              canonicalParam = canonicalizeResource(targetVal).uri;
            } catch (err) {
              throw new ExecutionSecurityError(
                `Parameter substitution attack detected: parameter "${paramKey}" is invalid: ${err.message}`,
                'PARAMETER_SUBSTITUTION_DETECTED'
              );
            }

            if (
              canonicalParam !== authorizedResource &&
              !matchResourcePattern(canonicalParam, authorizedResource)
            ) {
              throw new ExecutionSecurityError(
                `Parameter substitution attack detected: parameter "${paramKey}" ("${canonicalParam}") does not match authorized capability resource ("${authorizedResource}")`,
                'PARAMETER_SUBSTITUTION_DETECTED'
              );
            }
          }
        };

        for (const key of CANDIDATE_RESOURCE_KEYS) {
          const val = params[key];
          if (val !== undefined && val !== null) {
            if (Array.isArray(val)) {
              for (const item of val) {
                checkResourceTarget(key, item);
              }
            } else {
              checkResourceTarget(key, val);
            }
          }
        }

        // Check S3 bucket + key composite parameters if present
        if (
          params.bucket !== undefined &&
          params.bucket !== null &&
          params.key !== undefined &&
          params.key !== null &&
          typeof params.bucket === 'string' &&
          typeof params.key === 'string' &&
          params.bucket.trim().length > 0 &&
          params.key.trim().length > 0
        ) {
          const s3Uri = `s3://${params.bucket.trim()}/${params.key.trim().replace(/^\//, '')}`;
          checkResourceTarget('bucket/key', s3Uri);
        }

        // 3. Execution Parameter Measurement Extraction & Validation:
        // Protect against capability blast-radius bypass where caller invokes executor with params exceeding lease or authorized request
        const CANDIDATE_BYTE_KEYS = [
          'size',
          'bytes',
          'requestedBytes',
          'byteLength',
          'contentLength',
          'byteSize',
        ];

        const CANDIDATE_COUNT_KEYS = [
          'count',
          'requestedCount',
          'objectCount',
          'itemCount',
        ];

        let paramsBytes = null;
        let paramsBytesKey = null;

        for (const key of CANDIDATE_BYTE_KEYS) {
          const val = params[key];
          if (val !== undefined && val !== null) {
            let parsed;
            try {
              parsed = parseByteSize(val);
            } catch (err) {
              throw new ExecutionSecurityError(
                `Execution blocked for tool "${toolName}": invalid byte size parameter "${key}": ${err.message}`,
                'MALFORMED_MEASUREMENT'
              );
            }
            if (paramsBytes !== null && paramsBytes !== parsed) {
              throw new ExecutionSecurityError(
                `Parameter substitution attack detected: conflicting byte size parameters in execution payload ("${paramsBytesKey}"=${paramsBytes}B vs "${key}"=${parsed}B)`,
                'PARAMETER_SUBSTITUTION_DETECTED'
              );
            }
            paramsBytes = parsed;
            paramsBytesKey = key;
          }
        }

        let paramsCount = null;
        let paramsCountKey = null;

        for (const key of CANDIDATE_COUNT_KEYS) {
          const val = params[key];
          if (val !== undefined && val !== null) {
            let parsed;
            if (typeof val === 'number') {
              if (!Number.isSafeInteger(val) || val < 0) {
                throw new ExecutionSecurityError(
                  `Execution blocked for tool "${toolName}": invalid object count parameter "${key}": ${val}. Must be a safe non-negative integer.`,
                  'MALFORMED_MEASUREMENT'
                );
              }
              parsed = val;
            } else if (typeof val === 'string') {
              const trimmed = val.trim();
              if (!/^[0-9]+$/.test(trimmed)) {
                throw new ExecutionSecurityError(
                  `Execution blocked for tool "${toolName}": invalid object count parameter "${key}": "${val}". Expected digits only.`,
                  'MALFORMED_MEASUREMENT'
                );
              }
              const num = Number(trimmed);
              if (!Number.isSafeInteger(num) || num < 0) {
                throw new ExecutionSecurityError(
                  `Execution blocked for tool "${toolName}": invalid object count parameter "${key}": "${val}". Exceeds safe integer range.`,
                  'MALFORMED_MEASUREMENT'
                );
              }
              parsed = num;
            } else {
              throw new ExecutionSecurityError(
                `Execution blocked for tool "${toolName}": invalid object count parameter "${key}" type: ${typeof val}.`,
                'MALFORMED_MEASUREMENT'
              );
            }

            if (paramsCount !== null && paramsCount !== parsed) {
              throw new ExecutionSecurityError(
                `Parameter substitution attack detected: conflicting object count parameters in execution payload ("${paramsCountKey}"=${paramsCount} vs "${key}"=${parsed})`,
                'PARAMETER_SUBSTITUTION_DETECTED'
              );
            }
            paramsCount = parsed;
            paramsCountKey = key;
          }
        }

        // Extract authorized measurements from request context if present
        let requestBytes = null;
        let requestCount = null;

        if (request && typeof request === 'object') {
          const rawReqSize = request.requestedBytes !== undefined ? request.requestedBytes : request.size;
          if (rawReqSize !== undefined && rawReqSize !== null) {
            try {
              requestBytes = parseByteSize(rawReqSize);
            } catch (err) {
              throw new ExecutionSecurityError(
                `Execution blocked for tool "${toolName}": invalid byte size in request: ${err.message}`,
                'MALFORMED_REQUEST'
              );
            }
          }

          const rawReqCount = request.requestedCount !== undefined ? request.requestedCount : request.count;
          if (rawReqCount !== undefined && rawReqCount !== null) {
            if (typeof rawReqCount === 'number') {
              if (Number.isSafeInteger(rawReqCount) && rawReqCount >= 0) {
                requestCount = rawReqCount;
              }
            } else if (typeof rawReqCount === 'string') {
              const trimmed = rawReqCount.trim();
              if (/^[0-9]+$/.test(trimmed)) {
                const num = Number(trimmed);
                if (Number.isSafeInteger(num) && num >= 0) {
                  requestCount = num;
                }
              }
            }
          }
        }

        // A. Execution parameters must NOT exceed authorized request measurements
        if (requestBytes !== null && paramsBytes !== null && paramsBytes > requestBytes) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": execution parameter size (${paramsBytes}B) exceeds authorized request size (${requestBytes}B)`,
            'BYTE_LIMIT_EXCEEDED'
          );
        }

        if (requestCount !== null && paramsCount !== null && paramsCount > requestCount) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": execution parameter object count (${paramsCount}) exceeds authorized request count (${requestCount})`,
            'OBJECT_LIMIT_EXCEEDED'
          );
        }

        // B. Execution parameters must NOT exceed capability lease limits
        if (capability.constraints?.maxBytes !== null && paramsBytes !== null && paramsBytes > capability.constraints.maxBytes) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": execution parameter size (${paramsBytes}B) exceeds capability lease limit (${capability.constraints.maxBytes}B)`,
            'BYTE_LIMIT_EXCEEDED'
          );
        }

        if (capability.constraints?.maxObjects !== null && paramsCount !== null && paramsCount > capability.constraints.maxObjects) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": execution parameter object count (${paramsCount}) exceeds capability lease limit (${capability.constraints.maxObjects})`,
            'OBJECT_LIMIT_EXCEEDED'
          );
        }

        // 4. Construct Effective Request binding actual execution measurements
        const effectiveSize = paramsBytes !== null
          ? paramsBytes
          : (requestBytes !== null ? requestBytes : undefined);

        const effectiveCount = paramsCount !== null
          ? paramsCount
          : (requestCount !== null ? requestCount : undefined);

        const effectiveHasSnapshot = params.hasSnapshot !== undefined
          ? params.hasSnapshot
          : (params.snapshot !== undefined ? params.snapshot : (request?.hasSnapshot ?? request?.snapshot));

        const effectiveIsDryRun = params.isDryRun !== undefined
          ? params.isDryRun
          : (params.dryRun !== undefined ? params.dryRun : (request?.isDryRun ?? request?.dryRun));

        const effectiveRequest = {
          action: normalizedTool,
          resource: (request && (request.resource || request.rawResource)) || capability.resource,
          size: effectiveSize,
          count: effectiveCount,
          hasSnapshot: effectiveHasSnapshot,
          isDryRun: effectiveIsDryRun,
          justification: request?.justification,
          parameters: params,
        };

        const effectiveContext = context || {
          agentId: capability.subject.agentId,
          taskUid: capability.subject.taskUid,
          user: capability.subject.user,
        };

        // 5. Atomic Verification + Nonce Consumption
        const verification = verifyCapability(
          capability,
          guard.policy,
          effectiveRequest,
          effectiveContext,
          { signingKey, consume: true } // Atomic check & consume!
        );

        if (!verification.valid) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": ${verification.error}`,
            verification.code
          );
        }

        // 6. Inject verified immutable binding into execution params
        const verifiedExecutionParams = Object.freeze({
          ...params,
          _authorizedResource: capability.resource,
          _authorizedAction: capability.action,
          _authorizedBounds: Object.freeze({ ...capability.constraints }),
        });

        // 7. Safely execute underlying tool
        return await rawExecutor(verifiedExecutionParams, {
          capability,
          verified: true,
          nonce: capability.nonce,
        });
      };
    },

    /**
     * Executes an action through the complete governance pipeline:
     * Policy Evaluation -> Transformation Verification -> Capability Issuance -> Execution.
     *
     * @param {object} actionRequest Action request details
     * @param {object|string} agentContext Agent context
     * @param {Function} rawExecutor The actual tool implementation to run if permitted
     * @returns {Promise<{ executed: boolean, result?: any, decision: object, capability?: object, constrained?: boolean, error?: string }>}
     */
    async execute(actionRequest, agentContext, rawExecutor) {
      // Strict request normalization upfront (rejects malformed booleans like "false", 0, etc.)
      const normRequest = normalizeActionRequest(actionRequest);

      // 1. Evaluate policy
      const decision = guard.evaluate(normRequest, agentContext);

      // 2. If decision is denied or requires human escalation, block execution
      if (!decision.allowed && !decision.isConstrained) {
        return {
          executed: false,
          decision,
          error: `Operation not permitted: ${decision.outcome}. Reasons: ${decision.reasons.join(', ')}`,
        };
      }

      // 3. If decision is CONSTRAIN, verify transformation prerequisites using strictly normalized booleans
      if (decision.isConstrained) {
        if (decision.constraints?.requireSnapshot && !normRequest.hasSnapshot) {
          return {
            executed: false,
            constrained: true,
            decision,
            suggestedTransform: decision.suggestedTransform,
            error: `Execution blocked: action requires transformation step (${decision.suggestedTransform?.step || 'SNAPSHOT'}) before execution`,
          };
        }

        if (decision.constraints?.dryRunOnly && !normRequest.isDryRun) {
          return {
            executed: false,
            constrained: true,
            decision,
            suggestedTransform: decision.suggestedTransform,
            error: 'Execution blocked: action requires dry-run verification before live execution',
          };
        }
      }

      // 4. Issue ephemeral dynamic capability lease
      const capability = issueCapability({
        decision,
        request: normRequest,
        context: agentContext,
        options: { signingKey },
      });

      // 5. Wrap and execute via protected boundary
      const protectedTool = this.protect(normRequest.action, rawExecutor);

      const result = await protectedTool(
        actionRequest.parameters || {},
        {
          capability,
          request: normRequest,
          context: agentContext,
        }
      );

      return {
        executed: true,
        result,
        decision,
        capability,
      };
    },
  };
}
