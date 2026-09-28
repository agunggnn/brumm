/**
 * @file tool-adapter.mjs
 * Execution Boundary & Tool Guard Adapter.
 * Enforces dynamic capability verification and single-use nonce consumption
 * directly in front of tools, Cloud APIs, and OS processes to prevent authorization bypass.
 */

import {
  consumeCapability,
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
     * Prevents any direct invocation unless a valid, signed, unconsumed capability is presented.
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

        // Verify capability against current active policy
        const verification = verifyCapability(
          capability,
          guard.policy,
          request || { action: toolName, resource: params.resource || '*' },
          context || { agentId: capability.subject.agentId },
          { signingKey }
        );

        if (!verification.valid) {
          throw new ExecutionSecurityError(
            `Execution blocked for tool "${toolName}": ${verification.error}`,
            verification.code
          );
        }

        // Atomically consume capability (single-use replay defense)
        consumeCapability(capability);

        // Execute verified tool
        return await rawExecutor(params, { capability, verified: true });
      };
    },

    /**
     * Executes an action through the complete governance pipeline:
     * Policy Evaluation -> Capability Issuance -> Execution Verification -> Nonce Consumption -> Execution.
     *
     * @param {object} actionRequest Action request details
     * @param {object|string} agentContext Agent context
     * @param {Function} rawExecutor The actual tool implementation to run if permitted
     * @returns {Promise<{ executed: boolean, result?: any, decision: object, capability?: object }>}
     */
    async execute(actionRequest, agentContext, rawExecutor) {
      // 1. Evaluate policy
      const decision = guard.evaluate(actionRequest, agentContext);

      // 2. Check if operation is permitted or constrained
      if (!decision.allowed && !decision.isConstrained) {
        return {
          executed: false,
          decision,
          error: `Operation not permitted: ${decision.outcome}. Reasons: ${decision.reasons.join(', ')}`,
        };
      }

      // 3. Issue ephemeral dynamic capability lease
      const capability = issueCapability({
        decision,
        request: actionRequest,
        context: agentContext,
        options: { signingKey },
      });

      // 4. Wrap and execute via protected boundary
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
