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
import { ExecutionSecurityError } from '../core/errors.mjs';

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
      if (typeof rawExecutor !== 'function') {
        throw new TypeError(`Executor for tool "${toolName}" must be a function`);
      }

      return async function protectedExecutor(params = {}, securityContext = {}) {
        const { capability, request, context } = securityContext;

        if (!capability) {
          throw new ExecutionSecurityError(
            `Direct execution blocked for tool "${toolName}": missing Brumm dynamic capability lease`,
            'MISSING_CAPABILITY'
          );
        }

        // 1. Parameter Substitution Defense:
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

        // 2. Atomic Verification + Nonce Consumption
        const effectiveRequest = request || {
          action: toolName,
          resource: capability.resource,
        };

        const effectiveContext = context || {
          agentId: capability.subject.agentId,
          taskUid: capability.subject.taskUid,
          user: capability.subject.user,
        };

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

        // 3. Inject verified immutable binding into execution params
        const verifiedExecutionParams = Object.freeze({
          ...params,
          _authorizedResource: capability.resource,
          _authorizedAction: capability.action,
          _authorizedBounds: Object.freeze({ ...capability.constraints }),
        });

        // 4. Safely execute underlying tool
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
      // 1. Evaluate policy
      const decision = guard.evaluate(actionRequest, agentContext);

      // 2. If decision is denied or requires human escalation, block execution
      if (!decision.allowed && !decision.isConstrained) {
        return {
          executed: false,
          decision,
          error: `Operation not permitted: ${decision.outcome}. Reasons: ${decision.reasons.join(', ')}`,
        };
      }

      // 3. If decision is CONSTRAIN, verify transformation prerequisites
      if (decision.isConstrained) {
        const hasSnapshot = Boolean(actionRequest.hasSnapshot || actionRequest.snapshot);
        const isDryRun = Boolean(actionRequest.isDryRun || actionRequest.dryRun);

        if (decision.constraints?.requireSnapshot && !hasSnapshot) {
          return {
            executed: false,
            constrained: true,
            decision,
            suggestedTransform: decision.suggestedTransform,
            error: `Execution blocked: action requires transformation step (${decision.suggestedTransform?.step || 'SNAPSHOT'}) before execution`,
          };
        }

        if (decision.constraints?.dryRunOnly && !isDryRun) {
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
        request: actionRequest,
        context: agentContext,
        options: { signingKey },
      });

      // 5. Wrap and execute via protected boundary
      const protectedTool = this.protect(actionRequest.action, rawExecutor);

      const result = await protectedTool(
        actionRequest.parameters || {},
        {
          capability,
          request: actionRequest,
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
