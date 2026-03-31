// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

// Production Claude agent execution with retry, git checkpoints, and audit logging

import { fs, path } from 'zx';
import { query } from '@anthropic-ai/claude-agent-sdk';

import { isRetryableError, PentestError } from '../services/error-handling.js';
import { isSpendingCapBehavior } from '../utils/billing-detection.js';
import { Timer } from '../utils/metrics.js';
import { formatTimestamp } from '../utils/formatting.js';
import { AGENT_VALIDATORS, MCP_AGENT_MAPPING } from '../session-manager.js';
import { AuditSession } from '../audit/index.js';
import { createDonnaHelperServer } from '../../mcp-server/dist/index.js';
import { AGENTS } from '../session-manager.js';
import type { AgentName } from '../types/index.js';

import { dispatchMessage } from './message-handlers.js';
import { detectExecutionContext, formatErrorOutput, formatCompletionMessage } from './output-formatters.js';
import { createProgressManager } from './progress-manager.js';
import { createAuditLogger } from './audit-logger.js';
import { getActualModelName } from './router-utils.js';
import { resolveModelFromProfile, type ModelTier } from './models.js';
import { runOpenAIAgentLoop } from './openai-executor.js';
import type { ModelProfile, ResolvedModelEndpoint } from '../types/config.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { TurnBuffer } from '../temporal/activities.js';

declare global {
  var DONNA_DISABLE_LOADER: boolean | undefined;
}

export interface ClaudePromptResult {
  result?: string | null | undefined;
  success: boolean;
  duration: number;
  turns?: number | undefined;
  cost: number;
  model?: string | undefined;
  partialCost?: number | undefined;
  apiErrorDetected?: boolean | undefined;
  error?: string | undefined;
  errorType?: string | undefined;
  prompt?: string | undefined;
  retryable?: boolean | undefined;
}

interface StdioMcpServer {
  type: 'stdio';
  command: string;
  args: string[];
  env: Record<string, string>;
}

type McpServer = ReturnType<typeof createDonnaHelperServer> | StdioMcpServer;

// Configures MCP servers for agent execution, with Docker-specific Chromium handling
function buildMcpServers(
  sourceDir: string,
  agentName: string | null,
  logger: ActivityLogger
): Record<string, McpServer> {
  // 1. Create the donna-helper server (always present)
  const donnaHelperServer = createDonnaHelperServer(sourceDir);

  const mcpServers: Record<string, McpServer> = {
    'donna-helper': donnaHelperServer,
  };

  // 2. Look up the agent's Playwright MCP mapping
  if (agentName) {
    const promptTemplate = AGENTS[agentName as AgentName].promptTemplate;
    const playwrightMcpName = MCP_AGENT_MAPPING[promptTemplate as keyof typeof MCP_AGENT_MAPPING] || null;

    if (playwrightMcpName) {
      logger.info(`Assigned ${agentName} -> ${playwrightMcpName}`);

      const userDataDir = `/tmp/${playwrightMcpName}`;

      // 3. Configure Playwright MCP args with Docker/local browser handling
      const isDocker = process.env.DONNA_DOCKER === 'true';

      const mcpArgs: string[] = [
        '@playwright/mcp@0.0.68',
        '--isolated',
        '--user-data-dir', userDataDir,
      ];

      if (isDocker) {
        mcpArgs.push('--executable-path', '/usr/bin/chromium-browser');
        mcpArgs.push('--browser', 'chromium');
      }

      // NOTE: Explicit allowlist — the Playwright MCP subprocess must not inherit
      // secrets (API keys, AWS tokens) from the parent process.
      const MCP_ENV_ALLOWLIST = [
        'PATH', 'HOME', 'NODE_PATH', 'DISPLAY',
        'PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH',
      ] as const;

      const envVars: Record<string, string> = {
        PLAYWRIGHT_HEADLESS: 'true',
        ...(isDocker && { PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1' }),
      };

      for (const key of MCP_ENV_ALLOWLIST) {
        if (process.env[key]) {
          envVars[key] = process.env[key]!;
        }
      }

      for (const [key, value] of Object.entries(process.env)) {
        if (key.startsWith('XDG_') && value !== undefined) {
          envVars[key] = value;
        }
      }

      mcpServers[playwrightMcpName] = {
        type: 'stdio' as const,
        command: 'npx',
        args: mcpArgs,
        env: envVars,
      };
    }
  }

  // 4. Return configured servers
  return mcpServers;
}

function outputLines(lines: string[]): void {
  for (const line of lines) {
    console.log(line);
  }
}

async function writeErrorLog(
  err: Error & { code?: string; status?: number },
  sourceDir: string,
  fullPrompt: string,
  duration: number
): Promise<void> {
  try {
    const errorLog = {
      timestamp: formatTimestamp(),
      agent: 'claude-executor',
      error: {
        name: err.constructor.name,
        message: err.message,
        code: err.code,
        status: err.status,
        stack: err.stack
      },
      context: {
        sourceDir,
        prompt: fullPrompt.slice(0, 200) + '...',
        retryable: isRetryableError(err)
      },
      duration
    };
    const logPath = path.join(sourceDir, 'error.log');
    await fs.appendFile(logPath, JSON.stringify(errorLog) + '\n');
  } catch {
    // Best-effort error log writing - don't propagate failures
  }
}

export async function validateAgentOutput(
  result: ClaudePromptResult,
  agentName: string | null,
  sourceDir: string,
  logger: ActivityLogger
): Promise<boolean> {
  logger.info(`Validating ${agentName} agent output`);

  try {
    // Check if agent completed successfully
    if (!result.success || !result.result) {
      logger.error('Validation failed: Agent execution was unsuccessful');
      return false;
    }

    // Get validator function for this agent
    const validator = agentName ? AGENT_VALIDATORS[agentName as keyof typeof AGENT_VALIDATORS] : undefined;

    if (!validator) {
      logger.warn(`No validator found for agent "${agentName}" - assuming success`);
      logger.info('Validation passed: Unknown agent with successful result');
      return true;
    }

    logger.info(`Using validator for agent: ${agentName}`, { sourceDir });

    // Apply validation function
    const validationResult = await validator(sourceDir, logger);

    if (validationResult) {
      logger.info('Validation passed: Required files/structure present');
    } else {
      logger.error('Validation failed: Missing required deliverable files');
    }

    return validationResult;

  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    logger.error(`Validation failed with error: ${errMsg}`);
    return false;
  }
}

// Low-level SDK execution. Handles message streaming, progress, and audit logging.
// Exported for Temporal activities to call single-attempt execution.
export async function runClaudePrompt(
  prompt: string,
  sourceDir: string,
  context: string = '',
  description: string = 'Claude analysis',
  agentName: string | null = null,
  auditSession: AuditSession | null = null,
  logger: ActivityLogger,
  modelTier: ModelTier = 'medium',
  turnBuffer?: TurnBuffer,
  modelProfile?: ModelProfile
): Promise<ClaudePromptResult> {
  // Route to OpenAI executor for non-Anthropic models (Qwen, Llama, etc.)
  // These models have a base_url pointing to LiteLLM/vLLM.
  // The Claude Agent SDK is incompatible with these models, so we use
  // a native OpenAI chat completions agent loop instead.
  if (modelProfile?.base_url) {
    logger.info(`Routing to OpenAI executor (model profile has base_url: ${modelProfile.base_url})`);
    return runOpenAIAgentLoop(
      prompt, sourceDir, context, description, agentName,
      auditSession, logger, modelTier, turnBuffer, modelProfile
    );
  }

  // 1. Initialize timing and prompt
  const timer = new Timer(`agent-${description.toLowerCase().replace(/\s+/g, '-')}`);
  const fullPrompt = context ? `${context}\n\n${prompt}` : prompt;

  // 2. Set up progress and audit infrastructure
  const execContext = detectExecutionContext(description);
  const progress = createProgressManager(
    { description, useCleanOutput: execContext.useCleanOutput },
    global.DONNA_DISABLE_LOADER ?? false
  );
  const auditLogger = createAuditLogger(auditSession);

  logger.info(`Running Claude Code: ${description}...`);

  // 2b. Resolve working directory — use temp dir for black-box scans (no source code)
  let effectiveCwd = sourceDir;
  if (!sourceDir) {
    // Use a stable workspace dir (created by activity layer) or create a fallback temp dir
    const os = await import('os');
    const fallbackDir = path.join(os.default.tmpdir(), 'donna-blackbox-fallback');
    await fs.mkdirp(fallbackDir);
    effectiveCwd = fallbackDir;
    logger.info(`Black-box mode: using workspace ${effectiveCwd}`);
  }

  // 3. Configure MCP servers
  const mcpServers = buildMcpServers(effectiveCwd, agentName, logger);

  // 4. Resolve model and endpoint from profile (or legacy env vars)
  const endpoint: ResolvedModelEndpoint = resolveModelFromProfile(modelTier, modelProfile);

  if (modelProfile) {
    logger.info(`Model profile active: model=${endpoint.model}, base_url=${endpoint.base_url ?? 'default'}`);
  }

  // 5. Build env vars to pass to SDK subprocesses
  const sdkEnv: Record<string, string> = {
    CLAUDE_CODE_MAX_OUTPUT_TOKENS: process.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS || '64000',
  };

  // Read fresh OAuth token from credentials file if available (auto-refreshed by Claude CLI)
  const credentialsPath = path.join(process.env.HOME || '/tmp', '.claude', '.credentials.json');
  try {
    if (fs.existsSync(credentialsPath)) {
      const creds = JSON.parse(fs.readFileSync(credentialsPath, 'utf-8'));
      const freshToken = creds?.claudeAiOauth?.accessToken;
      if (freshToken) {
        sdkEnv.CLAUDE_CODE_OAUTH_TOKEN = freshToken;
        logger.info(`Using fresh OAuth token from ${credentialsPath}`);
      }
    }
  } catch {
    // Fall back to env var
  }

  const passthroughVars = [
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
    'ANTHROPIC_AUTH_TOKEN',
    'CLAUDE_CODE_USE_BEDROCK',
    'AWS_REGION',
    'AWS_BEARER_TOKEN_BEDROCK',
    'CLAUDE_CODE_USE_VERTEX',
    'CLOUD_ML_REGION',
    'ANTHROPIC_VERTEX_PROJECT_ID',
    'GOOGLE_APPLICATION_CREDENTIALS',
    'ANTHROPIC_SMALL_MODEL',
    'ANTHROPIC_MEDIUM_MODEL',
    'ANTHROPIC_LARGE_MODEL',
  ];
  for (const name of passthroughVars) {
    // Don't overwrite token if already set from credentials file
    if (process.env[name] && !sdkEnv[name]) {
      sdkEnv[name] = process.env[name]!;
    }
  }

  // 5b. Apply model profile endpoint overrides (takes precedence over env passthrough)
  if (endpoint.base_url) {
    sdkEnv.ANTHROPIC_BASE_URL = endpoint.base_url;
  }
  if (endpoint.api_key_env) {
    const apiKey = process.env[endpoint.api_key_env];
    if (apiKey) {
      sdkEnv.ANTHROPIC_API_KEY = apiKey;
    } else {
      logger.warn(`Model profile references env var ${endpoint.api_key_env} but it is not set`);
    }
  }

  // 6. Configure SDK options
  const options = {
    model: endpoint.model,
    maxTurns: 10_000,
    cwd: effectiveCwd,
    permissionMode: 'bypassPermissions' as const,
    allowDangerouslySkipPermissions: true,
    mcpServers,
    env: sdkEnv,
  };

  if (!execContext.useCleanOutput) {
    logger.info(`SDK Options: maxTurns=${options.maxTurns}, cwd=${effectiveCwd}, permissions=BYPASS`);
  }

  let turnCount = 0;
  let result: string | null = null;
  let apiErrorDetected = false;
  let totalCost = 0;

  progress.start();

  try {
    // 6. Process the message stream
    const messageLoopResult = await processMessageStream(
      fullPrompt,
      options,
      { execContext, description, progress, auditLogger, logger },
      timer,
      agentName,
      turnBuffer
    );

    turnCount = messageLoopResult.turnCount;
    result = messageLoopResult.result;
    apiErrorDetected = messageLoopResult.apiErrorDetected;
    totalCost = messageLoopResult.cost;
    const model = messageLoopResult.model;

    // === SPENDING CAP SAFEGUARD ===
    // 7. Defense-in-depth: Detect spending cap that slipped through detectApiError().
    // Uses consolidated billing detection from utils/billing-detection.ts
    if (isSpendingCapBehavior(turnCount, totalCost, result || '')) {
      throw new PentestError(
        `Spending cap likely reached (turns=${turnCount}, cost=$0): ${result?.slice(0, 100)}`,
        'billing',
        true // Retryable - Temporal will use 5-30 min backoff
      );
    }

    // 8. Finalize successful result
    const duration = timer.stop();

    if (apiErrorDetected) {
      logger.warn(`API Error detected in ${description} - will validate deliverables before failing`);
    }

    progress.finish(formatCompletionMessage(execContext, description, turnCount, duration));

    return {
      result,
      success: true,
      duration,
      turns: turnCount,
      cost: totalCost,
      model,
      partialCost: totalCost,
      apiErrorDetected
    };

  } catch (error) {
    // 9. Handle errors — log, write error file, return failure
    const duration = timer.stop();

    const err = error as Error & { code?: string; status?: number };

    await auditLogger.logError(err, duration, turnCount);
    progress.stop();
    outputLines(formatErrorOutput(err, execContext, description, duration, sourceDir, isRetryableError(err)));
    await writeErrorLog(err, sourceDir, fullPrompt, duration);

    return {
      error: err.message,
      errorType: err.constructor.name,
      prompt: fullPrompt.slice(0, 100) + '...',
      success: false,
      duration,
      cost: totalCost,
      retryable: isRetryableError(err)
    };
  }
}


interface MessageLoopResult {
  turnCount: number;
  result: string | null;
  apiErrorDetected: boolean;
  cost: number;
  model?: string | undefined;
}

interface MessageLoopDeps {
  execContext: ReturnType<typeof detectExecutionContext>;
  description: string;
  progress: ReturnType<typeof createProgressManager>;
  auditLogger: ReturnType<typeof createAuditLogger>;
  logger: ActivityLogger;
}

async function processMessageStream(
  fullPrompt: string,
  options: NonNullable<Parameters<typeof query>[0]['options']>,
  deps: MessageLoopDeps,
  timer: Timer,
  agentName: string | null = null,
  turnBuffer?: TurnBuffer
): Promise<MessageLoopResult> {
  const { execContext, description, progress, auditLogger, logger } = deps;
  const HEARTBEAT_INTERVAL = 30000;

  let turnCount = 0;
  let result: string | null = null;
  let apiErrorDetected = false;
  let cost = 0;
  let model: string | undefined;
  let lastHeartbeat = Date.now();

  for await (const message of query({ prompt: fullPrompt, options })) {
    // Heartbeat logging when loader is disabled
    const now = Date.now();
    if (global.DONNA_DISABLE_LOADER && now - lastHeartbeat > HEARTBEAT_INTERVAL) {
      logger.info(`[${Math.floor((now - timer.startTime) / 1000)}s] ${description} running... (Turn ${turnCount})`);
      lastHeartbeat = now;
    }

    // Increment turn count for assistant messages
    if (message.type === 'assistant') {
      turnCount++;

      // Push turn summary to heartbeat buffer for live dashboard streaming
      if (turnBuffer) {
        const msg = message as { message?: { content?: unknown } };
        let snippet = '';
        if (msg.message?.content) {
          if (Array.isArray(msg.message.content)) {
            const parts: string[] = [];
            for (const block of msg.message.content as Array<{ type?: string; text?: string; name?: string; input?: unknown }>) {
              if (block.type === 'text' && block.text) {
                parts.push(block.text);
              } else if (block.type === 'tool_use' && block.name) {
                // Summarize tool usage for live visibility
                const toolName = block.name;
                let param = '';
                if (block.input && typeof block.input === 'object') {
                  const inp = block.input as Record<string, unknown>;
                  // Extract the most useful parameter for each common tool
                  if (inp.command) param = String(inp.command).replace(/\n/g, ' ').slice(0, 80);
                  else if (inp.file_path) param = String(inp.file_path);
                  else if (inp.pattern) param = String(inp.pattern);
                  else if (inp.url) param = String(inp.url);
                  else if (inp.query) param = String(inp.query).slice(0, 80);
                  else {
                    // Use first string param
                    for (const v of Object.values(inp)) {
                      if (typeof v === 'string' && v.length > 0) { param = v.slice(0, 80); break; }
                    }
                  }
                }
                parts.push(param ? `🔧 ${toolName}: ${param}` : `🔧 ${toolName}`);
              }
            }
            snippet = parts.join(' | ');
          } else {
            snippet = String(msg.message.content);
          }
        }
        const label = agentName || description;
        const truncated = snippet.slice(0, 250).replace(/\n/g, ' ');
        turnBuffer.push(`Turn ${turnCount} (${label}): ${truncated}`);
      }
    }

    const dispatchResult = await dispatchMessage(
      message as { type: string; subtype?: string },
      turnCount,
      { execContext, description, progress, auditLogger, logger }
    );

    if (dispatchResult.type === 'throw') {
      throw dispatchResult.error;
    }

    if (dispatchResult.type === 'complete') {
      result = dispatchResult.result;
      cost = dispatchResult.cost;
      break;
    }

    if (dispatchResult.type === 'continue') {
      if (dispatchResult.apiErrorDetected) {
        apiErrorDetected = true;
      }
      // Capture model from SystemInitMessage, but override with router model if applicable
      if (dispatchResult.model) {
        model = getActualModelName(dispatchResult.model);
      }
    }
  }

  return { turnCount, result, apiErrorDetected, cost, model };
}
