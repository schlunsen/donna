#!/usr/bin/env node
// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Donna Sentinel — Continuous security monitoring.
 *
 * Starts a cron-scheduled workflow that monitors a git repo + web target
 * and runs incremental pentest pipelines on changes.
 *
 * Usage:
 *   npm run sentinel:start -- <webUrl> <repoPath> [options]
 *
 * Options:
 *   --schedule <cron>       Cron schedule (default: "0 *​/6 * * *" = every 6 hours)
 *   --config <path>         Configuration file path
 *   --branch <name>         Git branch to track (default: "main")
 *   --deploy-key <path>     SSH deploy key for git fetch
 *   --token-env <var>       Env var name holding git PAT
 *   --strategy <mode>       "incremental" or "full" (default: "incremental")
 *   --webhook <url>         Slack/Discord webhook for notifications
 *   --pipeline-testing      Use minimal prompts for fast testing
 *   --stop                  Stop an existing continuous workflow
 *
 * Setup (minimal git access):
 *   1. GitHub Deploy Key (recommended, read-only, single repo):
 *      ssh-keygen -t ed25519 -f ~/.ssh/donna-deploy -N "" -C "donna-scanner"
 *      Add public key at: Repo → Settings → Deploy keys (leave write access UNCHECKED)
 *
 *   2. Fine-Grained PAT (read-only, specific repos):
 *      GitHub → Settings → Developer settings → Fine-grained tokens
 *      Permission needed: Contents → Read-only
 *      Then: export DONNA_GIT_TOKEN="ghp_..." and use --token-env DONNA_GIT_TOKEN
 *
 *   3. GitHub App (for organizations, auto-rotating tokens):
 *      Create app with Repository contents: Read permission
 *      Install on target repos
 *
 * Environment:
 *   TEMPORAL_ADDRESS - Temporal server address (default: localhost:7233)
 */

import { Connection, Client, WorkflowNotFoundError } from '@temporalio/client';
import dotenv from 'dotenv';
import { parseConfig } from '../config-parser.js';
import { sanitizeHostname } from '../audit/utils.js';
import type { ContinuousInput } from './continuous-shared.js';
import type { PipelineConfig, ContinuousConfig } from '../types/config.js';

dotenv.config();

/** Return the first defined value, or undefined if none. */
function getDefinedValue(...values: (string | undefined)[]): string | undefined {
  return values.find((v) => v !== undefined);
}

// ── CLI Parsing ─────────────────────────────────────────────────

interface ContinuousCliArgs {
  webUrl: string;
  repoPath: string;
  schedule: string;
  configPath?: string;
  outputPath?: string;
  gitBranch: string;
  gitRemote: string;
  gitDeployKey?: string;
  gitTokenEnv?: string;
  strategy: 'incremental' | 'full';
  fullScanEveryDays: number;
  webhookUrl?: string;
  pipelineTestingMode: boolean;
  customWorkflowId?: string;
  stopWorkflow: boolean;
}

function showUsage(): void {
  console.log('\n🛡️  Donna Sentinel — Continuous Security Monitoring');
  console.log('Monitor a target and run incremental pentests on changes\n');
  console.log('Usage:');
  console.log('  node dist/temporal/continuous-client.js <webUrl> <repoPath> [options]\n');
  console.log('Options:');
  console.log('  --schedule <cron>      Cron schedule (default: every 6 hours)');
  console.log('  --config <path>        Configuration file path');
  console.log('  --branch <name>        Git branch to track (default: main)');
  console.log('  --remote <name>        Git remote name (default: origin)');
  console.log('  --deploy-key <path>    SSH deploy key path');
  console.log('  --token-env <var>      Env var name with git token');
  console.log('  --strategy <mode>      incremental or full (default: incremental)');
  console.log('  --full-scan-days <n>   Days between full scans (default: 7)');
  console.log('  --webhook <url>        Slack/Discord webhook URL');
  console.log('  --pipeline-testing     Use minimal prompts for fast testing');
  console.log('  --workflow-id <id>     Custom workflow ID');
  console.log('  --stop                 Stop an existing continuous workflow\n');
  console.log('Git Access Setup (minimum permissions):');
  console.log('  Deploy key:  ssh-keygen -t ed25519 -f ~/.ssh/donna-deploy -N ""');
  console.log('               Add at: Repo → Settings → Deploy keys (read-only)');
  console.log('  PAT:         GitHub → Settings → Fine-grained tokens');
  console.log('               Permission: Contents → Read-only\n');
  console.log('Examples:');
  console.log('  # Start continuous scanning with deploy key');
  console.log('  node dist/temporal/continuous-client.js https://app.example.com ./repos/app \\');
  console.log('    --deploy-key ~/.ssh/donna-deploy --webhook https://hooks.slack.com/T00/B00/xxx');
  console.log('');
  console.log('  # Start with token auth, full scans every 3 days');
  console.log('  node dist/temporal/continuous-client.js https://app.example.com ./repos/app \\');
  console.log('    --token-env DONNA_GIT_TOKEN --full-scan-days 3');
  console.log('');
  console.log('  # Stop a running continuous workflow');
  console.log('  node dist/temporal/continuous-client.js --stop --workflow-id donna-continuous-myapp\n');
}

function parseCliArgs(argv: string[]): ContinuousCliArgs {
  if (argv.includes('--help') || argv.includes('-h')) {
    showUsage();
    process.exit(0);
  }

  let webUrl: string | undefined;
  let repoPath: string | undefined;
  let schedule = '0 */6 * * *';
  let configPath: string | undefined;
  let outputPath: string | undefined;
  let gitBranch = 'main';
  let gitRemote = 'origin';
  let gitDeployKey: string | undefined;
  let gitTokenEnv: string | undefined;
  let strategy: 'incremental' | 'full' = 'incremental';
  let fullScanEveryDays = 7;
  let webhookUrl: string | undefined;
  let pipelineTestingMode = false;
  let customWorkflowId: string | undefined;
  let stopWorkflow = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    const hasNext = next && !next.startsWith('-');

    if (arg === '--schedule' && hasNext) { schedule = next; i++; }
    else if (arg === '--config' && hasNext) { configPath = next; i++; }
    else if (arg === '--output' && hasNext) { outputPath = next; i++; }
    else if (arg === '--branch' && hasNext) { gitBranch = next; i++; }
    else if (arg === '--remote' && hasNext) { gitRemote = next; i++; }
    else if (arg === '--deploy-key' && hasNext) { gitDeployKey = next; i++; }
    else if (arg === '--token-env' && hasNext) { gitTokenEnv = next; i++; }
    else if (arg === '--strategy' && hasNext) { strategy = next as 'incremental' | 'full'; i++; }
    else if (arg === '--full-scan-days' && hasNext) { fullScanEveryDays = parseInt(next, 10); i++; }
    else if (arg === '--webhook' && hasNext) { webhookUrl = next; i++; }
    else if (arg === '--workflow-id' && hasNext) { customWorkflowId = next; i++; }
    else if (arg === '--pipeline-testing') { pipelineTestingMode = true; }
    else if (arg === '--stop') { stopWorkflow = true; }
    else if (arg && !arg.startsWith('-')) {
      if (!webUrl) webUrl = arg;
      else if (!repoPath) repoPath = arg;
    }
  }

  if (stopWorkflow && customWorkflowId) {
    return {
      webUrl: '', repoPath: '', schedule, gitBranch, gitRemote,
      strategy, fullScanEveryDays, pipelineTestingMode,
      customWorkflowId, stopWorkflow,
    };
  }

  if (!webUrl || !repoPath) {
    console.error('Error: webUrl and repoPath are required');
    showUsage();
    process.exit(1);
  }

  return {
    webUrl, repoPath, schedule, gitBranch, gitRemote,
    strategy, fullScanEveryDays, pipelineTestingMode, stopWorkflow,
    ...(configPath && { configPath }),
    ...(outputPath && { outputPath }),
    ...(gitDeployKey && { gitDeployKey }),
    ...(gitTokenEnv && { gitTokenEnv }),
    ...(webhookUrl && { webhookUrl }),
    ...(customWorkflowId && { customWorkflowId }),
  };
}

// ── Main ────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseCliArgs(process.argv.slice(2));

  const address = process.env.TEMPORAL_ADDRESS || 'localhost:7233';
  console.log(`Connecting to Temporal at ${address}...`);

  const connection = await Connection.connect({ address });
  const client = new Client({ connection });

  try {
    // Handle --stop
    if (args.stopWorkflow) {
      if (!args.customWorkflowId) {
        console.error('Error: --workflow-id is required with --stop');
        process.exit(1);
      }
      try {
        const handle = client.workflow.getHandle(args.customWorkflowId);
        await handle.terminate('Stopped by user');
        console.log(`✓ Stopped workflow: ${args.customWorkflowId}`);
      } catch (error) {
        if (error instanceof WorkflowNotFoundError) {
          console.log(`Workflow not found: ${args.customWorkflowId}`);
        } else {
          throw error;
        }
      }
      return;
    }

    // Load continuous config from config file if available
    let continuousConfig: ContinuousConfig | undefined;
    let pipelineConfig: PipelineConfig | undefined;

    if (args.configPath) {
      try {
        const config = await parseConfig(args.configPath);
        continuousConfig = config.continuous;
        if (config.pipeline) {
          pipelineConfig = {};
          if (config.pipeline.retry_preset) pipelineConfig.retry_preset = config.pipeline.retry_preset;
          if (config.pipeline.max_concurrent_pipelines) {
            pipelineConfig.max_concurrent_pipelines = Number(config.pipeline.max_concurrent_pipelines);
          }
        }
      } catch {
        // Config errors will surface in preflight
      }
    }

    // CLI args override config file
    const schedule = args.schedule !== '0 */6 * * *'
      ? args.schedule
      : (continuousConfig?.schedule ?? args.schedule);

    const hostname = sanitizeHostname(args.webUrl);
    const workflowId = args.customWorkflowId ?? `donna-continuous-${hostname}`;

    const input: ContinuousInput = {
      webUrl: args.webUrl,
      repoPath: args.repoPath,
      gitRemote: args.gitRemote !== 'origin' ? args.gitRemote : (continuousConfig?.git_remote ?? 'origin'),
      gitBranch: args.gitBranch !== 'main' ? args.gitBranch : (continuousConfig?.git_branch ?? 'main'),
      strategy: args.strategy !== 'incremental' ? args.strategy : (continuousConfig?.strategy ?? 'incremental'),
      fullScanEveryDays: args.fullScanEveryDays !== 7
        ? args.fullScanEveryDays
        : (continuousConfig?.full_scan_every_days ?? 7),
      ...(args.configPath && { configPath: args.configPath }),
      ...(args.outputPath && { outputPath: args.outputPath }),
      ...(args.pipelineTestingMode && { pipelineTestingMode: true }),
      ...(getDefinedValue(args.gitDeployKey, continuousConfig?.git_deploy_key) !== undefined && {
        gitDeployKey: getDefinedValue(args.gitDeployKey, continuousConfig?.git_deploy_key)!,
      }),
      ...(getDefinedValue(args.gitTokenEnv, continuousConfig?.git_token_env) !== undefined && {
        gitTokenEnv: getDefinedValue(args.gitTokenEnv, continuousConfig?.git_token_env)!,
      }),
      ...(getDefinedValue(args.webhookUrl, continuousConfig?.notifications?.webhook_url) !== undefined && {
        notificationWebhook: getDefinedValue(args.webhookUrl, continuousConfig?.notifications?.webhook_url)!,
      }),
      ...(pipelineConfig && { pipelineConfig }),
    };

    // Start the cron workflow
    await client.workflow.start('continuousPentestWorkflow', {
      taskQueue: 'donna-pipeline',
      workflowId,
      cronSchedule: schedule,
      args: [input],
    });

    console.log('\n🛡️  Donna Sentinel activated!');
    console.log();
    console.log(`  Workflow ID:  ${workflowId}`);
    console.log(`  Schedule:     ${schedule}`);
    console.log(`  Target:       ${args.webUrl}`);
    console.log(`  Repository:   ${args.repoPath}`);
    console.log(`  Branch:       ${input.gitBranch}`);
    console.log(`  Strategy:     ${input.strategy}`);
    if (input.gitDeployKey) console.log(`  Auth:         Deploy key (${input.gitDeployKey})`);
    if (input.gitTokenEnv) console.log(`  Auth:         Token from $${input.gitTokenEnv}`);
    if (input.notificationWebhook) console.log(`  Webhook:      Configured`);
    console.log();
    console.log('Monitor:');
    console.log(`  Web UI:  http://localhost:8233/namespaces/default/workflows/${workflowId}`);
    console.log(`  Stop:    node dist/temporal/continuous-client.js --stop --workflow-id ${workflowId}`);
    console.log();
  } finally {
    await connection.close();
  }
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
