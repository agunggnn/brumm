#!/usr/bin/env node
/**
 * @file bin/brumm.mjs
 * Brumm CLI — Agentic Governance & Policy Simulation Tool.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { evaluatePolicy } from '../src/core/policy-engine.mjs';
import { loadPolicyFile } from '../src/core/policy-loader.mjs';

const VERSION = '0.1.0';
const DEFAULT_BUNDLED_POLICY_PATH = fileURLToPath(new URL('../brumm-policy.yaml', import.meta.url));

const HELP_TEXT = `
Brumm 🐻🛡️ — The Denial Smart Boss for AI Agents
Version: ${VERSION}

USAGE:
  brumm policy test --action <action> --resource <target> [options]
  brumm evaluate --action <action> --resource <target> [options]
  brumm --help
  brumm --version

OPTIONS:
  -p, --policy <path>     Path to YAML or JSON policy file (default: ./brumm-policy.yaml or bundled policy)
  -a, --agent <id>        Agent identifier (default: test-agent)
  -u, --user <id>         User/subject identifier (default: system)
      --action <action>   Action name (e.g. delete, read, deploy, restart)
  -r, --resource <path>   Resource target (e.g. backup-prod/*, /data/prod)
  -s, --size <size>       Requested data volume (e.g. 700GB, 50MB, 1000)
  -c, --count <count>     Requested object count (non-negative integer)
      --snapshot          Declare that a pre-execution snapshot exists
      --dry-run           Declare dry-run simulation mode
  -e, --env <name>        Environment tier (e.g. production, staging, development)
      --json              Output full decision as JSON
  -h, --help              Show this help menu
  -v, --version           Print version information

EXAMPLES:
  # Simulate cleanup-agent requesting 700GB deletion on production backup
  brumm policy test \\
    --agent cleanup-agent \\
    --action delete \\
    --resource backup-prod \\
    --size 700GB \\
    --env production
`;

function main() {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
    console.log(HELP_TEXT.trim());
    process.exit(0);
  }

  if (argv.includes('-v') || argv.includes('--version')) {
    console.log(`brumm v${VERSION}`);
    process.exit(0);
  }

  const subcommand = argv[0];
  const subArgs = argv.slice(1);

  if (subcommand === 'policy' && subArgs[0] === 'test') {
    handlePolicyTest(subArgs.slice(1));
  } else if (subcommand === 'test' || subcommand === 'evaluate') {
    handlePolicyTest(subArgs);
  } else {
    console.error(`Unknown command: "${subcommand}". Run "brumm --help" for usage.`);
    process.exit(1);
  }
}

function resolvePolicyPath(explicitPolicyOption) {
  if (explicitPolicyOption) {
    return resolve(process.cwd(), explicitPolicyOption);
  }
  if (process.env.BRUMM_POLICY_PATH) {
    return resolve(process.cwd(), process.env.BRUMM_POLICY_PATH);
  }
  const cwdDefault = resolve(process.cwd(), 'brumm-policy.yaml');
  if (existsSync(cwdDefault)) {
    return cwdDefault;
  }
  return DEFAULT_BUNDLED_POLICY_PATH;
}

function handlePolicyTest(args) {
  const options = {
    policy: { type: 'string', short: 'p' },
    agent: { type: 'string', short: 'a', default: 'test-agent' },
    user: { type: 'string', short: 'u', default: 'system' },
    action: { type: 'string' },
    resource: { type: 'string', short: 'r' },
    size: { type: 'string', short: 's' },
    count: { type: 'string', short: 'c' },
    snapshot: { type: 'boolean', default: false },
    'dry-run': { type: 'boolean', default: false },
    env: { type: 'string', short: 'e', default: 'development' },
    json: { type: 'boolean', default: false },
  };

  let values;
  try {
    const parsed = parseArgs({ args, options, allowPositionals: true });
    values = parsed.values;
  } catch (err) {
    console.error(`Error parsing arguments: ${err.message}`);
    process.exit(1);
  }

  if (!values.action) {
    console.error('Error: --action is required. Example: --action delete');
    process.exit(1);
  }

  if (!values.resource) {
    console.error('Error: --resource is required. Example: --resource backup-prod/2024');
    process.exit(1);
  }

  const policyPath = resolvePolicyPath(values.policy);
  if (!existsSync(policyPath)) {
    console.error(`Error: Policy file not found: "${policyPath}"`);
    process.exit(1);
  }

  let compiledPolicy;
  try {
    compiledPolicy = loadPolicyFile(policyPath);
  } catch (err) {
    console.error(`Error loading policy file: ${err.message}`);
    process.exit(1);
  }

  const request = {
    action: values.action,
    resource: values.resource,
    size: values.size,
    count: values.count,
    hasSnapshot: values.snapshot,
    isDryRun: values['dry-run'],
  };

  const context = {
    agentId: values.agent,
    environment: values.env,
    user: values.user,
  };

  const decision = evaluatePolicy(compiledPolicy, request, context);

  if (values.json) {
    console.log(JSON.stringify(decision, null, 2));
  } else {
    console.log(`\nDecision: ${decision.outcome}`);
    if (decision.matchedRule) {
      console.log(`Rule:     ${decision.matchedRule}`);
    }
    console.log(`Policy:   ${compiledPolicy.name} (hash: ${compiledPolicy.hash.slice(0, 8)})`);

    if (decision.reasons && decision.reasons.length > 0) {
      console.log('\nReasons:');
      for (const reason of decision.reasons) {
        console.log(`- ${reason}`);
      }
    }

    if (decision.suggestedTransform) {
      console.log('\nSuggested Safe Transformation:');
      console.log(`  Next Step: ${decision.suggestedTransform.step}`);
      console.log(`  Pipeline:  ${decision.suggestedTransform.pipeline.join(' -> ')}`);
    }
    console.log('');
  }

  // Exit codes reflecting outcome:
  // 0: ALLOW, 1: DENY, 2: ESCALATE, 3: CONSTRAIN
  switch (decision.outcome) {
    case 'ALLOW':
      process.exit(0);
      break;
    case 'DENY':
      process.exit(1);
      break;
    case 'ESCALATE':
      process.exit(2);
      break;
    case 'CONSTRAIN':
      process.exit(3);
      break;
    default:
      process.exit(1);
  }
}

main();
