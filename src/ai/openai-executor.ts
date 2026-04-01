// Donna - Continuous AI Pentesting Platform
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * OpenAI-Compatible Agent Executor
 *
 * A standalone agent loop for non-Anthropic models (Qwen, Llama, etc.)
 * that speaks native OpenAI chat completions format.
 *
 * Why this exists:
 * The Claude Agent SDK is designed for Claude and causes cascading
 * compatibility issues with non-Anthropic models. Going direct to vLLM
 * (bypassing LiteLLM) provides significant speed improvements.
 *
 * This executor:
 * 1. Talks directly to vLLM via /v1/chat/completions (native OpenAI format)
 * 2. Implements core tools natively (Bash, Read, Write, Glob, Grep)
 * 3. Calls donna-helper tools directly (no MCP layer)
 * 4. Returns the same ClaudePromptResult for pipeline compatibility
 */

import { fs, path } from 'zx';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Timer } from '../utils/metrics.js';
import type { AuditSession } from '../audit/index.js';
import { resolveModelFromProfile, type ModelTier } from './models.js';
import type { ModelProfile, ResolvedModelEndpoint } from '../types/config.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { TurnBuffer } from '../temporal/activities.js';
import type { ClaudePromptResult } from './claude-executor.js';

// ── Inline deliverable logic (from mcp-server, to avoid cross-package imports) ──

const DELIVERABLE_FILENAMES: Record<string, string> = {
  CODE_ANALYSIS: 'code_analysis_deliverable.md',
  RECON: 'recon_deliverable.md',
  INJECTION_ANALYSIS: 'injection_analysis_deliverable.md',
  INJECTION_QUEUE: 'injection_exploitation_queue.json',
  XSS_ANALYSIS: 'xss_analysis_deliverable.md',
  XSS_QUEUE: 'xss_exploitation_queue.json',
  AUTH_ANALYSIS: 'auth_analysis_deliverable.md',
  AUTH_QUEUE: 'auth_exploitation_queue.json',
  AUTHZ_ANALYSIS: 'authz_analysis_deliverable.md',
  AUTHZ_QUEUE: 'authz_exploitation_queue.json',
  SSRF_ANALYSIS: 'ssrf_analysis_deliverable.md',
  SSRF_QUEUE: 'ssrf_exploitation_queue.json',
  INJECTION_EVIDENCE: 'injection_exploitation_evidence.md',
  XSS_EVIDENCE: 'xss_exploitation_evidence.md',
  AUTH_EVIDENCE: 'auth_exploitation_evidence.md',
  AUTHZ_EVIDENCE: 'authz_exploitation_evidence.md',
  SSRF_EVIDENCE: 'ssrf_exploitation_evidence.md',
};

const QUEUE_TYPES = new Set([
  'INJECTION_QUEUE', 'XSS_QUEUE', 'AUTH_QUEUE', 'AUTHZ_QUEUE', 'SSRF_QUEUE',
]);

function isQueueType(type: string): boolean {
  return QUEUE_TYPES.has(type);
}

function validateQueueJson(content: string): { valid: boolean; message?: string } {
  try {
    const parsed = JSON.parse(content);
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.vulnerabilities)) {
      return { valid: false, message: 'Must have {"vulnerabilities": [...]} structure' };
    }
    return { valid: true };
  } catch {
    return { valid: false, message: 'Invalid JSON' };
  }
}

function saveDeliverableFile(targetDir: string, filename: string, content: string): string {
  const deliverablesDir = path.join(targetDir, 'deliverables');
  const filepath = path.join(deliverablesDir, filename);
  fs.mkdirpSync(deliverablesDir);
  fs.writeFileSync(filepath, content, 'utf8');
  return filepath;
}

const execAsync = promisify(exec);

// ── Types ──────────────────────────────────────────────────────

interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
}

interface OpenAIToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
}

interface OpenAITool {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
}

interface OpenAIChatResponse {
  id: string;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string | null;
      tool_calls?: OpenAIToolCall[];
      reasoning?: string;
    };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

// ── Tool Definitions ───────────────────────────────────────────

function buildToolDefinitions(): OpenAITool[] {
  return [
    {
      type: 'function',
      function: {
        name: 'bash',
        description: 'Execute a bash command and return its output. Use for running security tools (nmap, subfinder, whatweb, etc.), creating directories, and other shell operations.',
        parameters: {
          type: 'object',
          properties: {
            command: { type: 'string', description: 'The bash command to execute' },
            timeout: { type: 'number', description: 'Timeout in milliseconds (default: 120000)' },
          },
          required: ['command'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'read_file',
        description: 'Read the contents of a file. Returns the file content as a string.',
        parameters: {
          type: 'object',
          properties: {
            file_path: { type: 'string', description: 'Absolute or relative path to the file' },
            offset: { type: 'number', description: 'Line number to start reading from (0-based)' },
            limit: { type: 'number', description: 'Maximum number of lines to read' },
          },
          required: ['file_path'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'write_file',
        description: 'Write content to a file. Creates the file if it doesn\'t exist, overwrites if it does.',
        parameters: {
          type: 'object',
          properties: {
            file_path: { type: 'string', description: 'Path to the file to write' },
            content: { type: 'string', description: 'Content to write to the file' },
          },
          required: ['file_path', 'content'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'glob_search',
        description: 'Search for files matching a glob pattern. Returns a list of matching file paths.',
        parameters: {
          type: 'object',
          properties: {
            pattern: { type: 'string', description: 'Glob pattern (e.g., "**/*.ts", "src/**/*.js")' },
            cwd: { type: 'string', description: 'Directory to search in (defaults to working directory)' },
          },
          required: ['pattern'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'grep_search',
        description: 'Search file contents using a regex pattern. Returns matching lines with file paths and line numbers.',
        parameters: {
          type: 'object',
          properties: {
            pattern: { type: 'string', description: 'Regex pattern to search for' },
            path: { type: 'string', description: 'File or directory to search in' },
            include: { type: 'string', description: 'Glob pattern to filter files (e.g., "*.ts")' },
          },
          required: ['pattern'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'list_directory',
        description: 'List files and directories in a given path.',
        parameters: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Directory path to list' },
          },
          required: ['path'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'save_deliverable',
        description: 'Save a deliverable file for the current agent. Queue files (types ending in _QUEUE) must have {"vulnerabilities": [...]} JSON structure. For large reports, write the file to disk first then pass file_path instead of inline content.',
        parameters: {
          type: 'object',
          properties: {
            deliverable_type: {
              type: 'string',
              enum: Object.keys(DELIVERABLE_FILENAMES),
              description: 'Type of deliverable to save',
            },
            content: {
              type: 'string',
              description: 'File content (markdown for analysis, JSON for queues). Optional if file_path is provided.',
            },
            file_path: {
              type: 'string',
              description: 'Path to a file whose contents should be used as the deliverable content.',
            },
          },
          required: ['deliverable_type'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'generate_totp',
        description: 'Generate a 6-digit TOTP code for authentication testing.',
        parameters: {
          type: 'object',
          properties: {
            secret: { type: 'string', description: 'Base32-encoded TOTP secret' },
          },
          required: ['secret'],
        },
      },
    },
  ];
}

// ── Tool Execution ─────────────────────────────────────────────

async function executeTool(
  name: string,
  args: Record<string, unknown>,
  cwd: string,
  logger: ActivityLogger
): Promise<string> {
  try {
    switch (name) {
      case 'bash': {
        const command = String(args.command ?? '');
        const timeout = Number(args.timeout ?? 120000);
        logger.info(`[tool] bash: ${command.slice(0, 100)}`);
        try {
          const { stdout, stderr } = await execAsync(command, {
            cwd,
            timeout,
            maxBuffer: 10 * 1024 * 1024, // 10MB
            env: { ...process.env, HOME: process.env.HOME ?? '/tmp' },
          });
          const output = stdout + (stderr ? `\nSTDERR: ${stderr}` : '');
          return output.slice(0, 50000) || '(no output)';
        } catch (execErr) {
          const e = execErr as { stdout?: string; stderr?: string; message: string };
          return `Error: ${e.message}\n${e.stdout ?? ''}${e.stderr ?? ''}`.slice(0, 50000);
        }
      }

      case 'read_file': {
        const filePath = resolvePath(String(args.file_path ?? ''), cwd);
        logger.info(`[tool] read_file: ${filePath}`);
        const content = await fs.readFile(filePath, 'utf-8');
        const lines = content.split('\n');
        const offset = Number(args.offset ?? 0);
        const limit = Number(args.limit ?? lines.length);
        const sliced = lines.slice(offset, offset + limit);
        return sliced.map((line: string, i: number) => `${offset + i + 1}\t${line}`).join('\n').slice(0, 50000);
      }

      case 'write_file': {
        const filePath = resolvePath(String(args.file_path ?? ''), cwd);
        logger.info(`[tool] write_file: ${filePath}`);
        await fs.mkdirp(path.dirname(filePath));
        await fs.writeFile(filePath, String(args.content ?? ''));
        return `File written: ${filePath}`;
      }

      case 'glob_search': {
        const pattern = String(args.pattern ?? '');
        const searchCwd = String(args.cwd ?? cwd);
        logger.info(`[tool] glob: ${pattern}`);
        try {
          const { stdout } = await execAsync(
            `find ${JSON.stringify(searchCwd)} -path ${JSON.stringify(pattern)} 2>/dev/null | head -200`,
            { cwd, timeout: 15000, maxBuffer: 2 * 1024 * 1024 }
          );
          return stdout.trim() || 'No files matched the pattern.';
        } catch {
          return 'No files matched the pattern.';
        }
      }

      case 'grep_search': {
        const pattern = String(args.pattern ?? '');
        const searchPath = String(args.path ?? cwd);
        const include = args.include ? `--include='${args.include}'` : '';
        logger.info(`[tool] grep: ${pattern}`);
        try {
          const { stdout } = await execAsync(
            `grep -rn ${include} -E ${JSON.stringify(pattern)} ${JSON.stringify(searchPath)} | head -100`,
            { cwd, timeout: 30000, maxBuffer: 5 * 1024 * 1024 }
          );
          return stdout || 'No matches found.';
        } catch {
          return 'No matches found.';
        }
      }

      case 'list_directory': {
        const dirPath = resolvePath(String(args.path ?? '.'), cwd);
        logger.info(`[tool] ls: ${dirPath}`);
        try {
          const entries = await fs.readdir(dirPath, { withFileTypes: true });
          return entries
            .map((e: { isDirectory: () => boolean; name: string }) => `${e.isDirectory() ? 'd' : '-'} ${e.name}`)
            .join('\n') || '(empty directory)';
        } catch {
          return `Error: Cannot read directory ${dirPath}`;
        }
      }

      case 'save_deliverable': {
        const deliverableType = String(args.deliverable_type ?? '');
        const content = args.content ? String(args.content) : undefined;
        const filePath = args.file_path ? String(args.file_path) : undefined;
        logger.info(`[tool] save_deliverable: ${deliverableType}`);

        // Resolve content from inline or file
        let resolvedContent: string;
        if (content) {
          resolvedContent = content;
        } else if (filePath) {
          const resolvedPath = path.isAbsolute(filePath) ? filePath : path.resolve(cwd, filePath);
          resolvedContent = await fs.readFile(resolvedPath, 'utf-8');
        } else {
          return 'Error: Either "content" or "file_path" must be provided';
        }

        // Validate queue JSON
        if (isQueueType(deliverableType)) {
          const validation = validateQueueJson(resolvedContent);
          if (!validation.valid) {
            return `Validation error: ${validation.message ?? 'Invalid queue JSON'}. Expected format: {"vulnerabilities": [...]}`;
          }
        }

        const filename = DELIVERABLE_FILENAMES[deliverableType];
        if (!filename) {
          return `Error: Unknown deliverable type "${deliverableType}". Valid types: ${Object.keys(DELIVERABLE_FILENAMES).join(', ')}`;
        }

        const savedPath = saveDeliverableFile(cwd, filename, resolvedContent);
        return `Deliverable saved successfully: ${savedPath}`;
      }

      case 'generate_totp': {
        // Simple TOTP generation — import from compiled mcp-server dist
        try {
          const { generateTotp: genTotp } = await import('../../mcp-server/dist/tools/generate-totp.js');
          const result = await genTotp({ secret: String(args.secret ?? '') });
          return JSON.stringify(result);
        } catch (e) {
          return `TOTP generation not available: ${e instanceof Error ? e.message : String(e)}`;
        }
      }

      default:
        return `Error: Unknown tool "${name}"`;
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return `Error executing ${name}: ${msg}`;
  }
}

function resolvePath(filePath: string, cwd: string): string {
  return path.isAbsolute(filePath) ? filePath : path.resolve(cwd, filePath);
}

// ── Main Agent Loop ────────────────────────────────────────────

const MAX_TURNS = 200;
const MAX_CONSECUTIVE_ERRORS = 5;

export async function runOpenAIAgentLoop(
  prompt: string,
  sourceDir: string,
  context: string = '',
  description: string = 'Agent analysis',
  agentName: string | null = null,
  _auditSession: AuditSession | null = null,
  logger: ActivityLogger,
  modelTier: ModelTier = 'medium',
  turnBuffer?: TurnBuffer,
  modelProfile?: ModelProfile
): Promise<ClaudePromptResult> {
  const timer = new Timer(`openai-agent-${description.toLowerCase().replace(/\s+/g, '-')}`);
  const fullPrompt = context ? `${context}\n\n${prompt}` : prompt;

  // Resolve working directory
  let effectiveCwd = sourceDir;
  if (!sourceDir) {
    const os = await import('os');
    const fallbackDir = path.join(os.default.tmpdir(), 'donna-blackbox-fallback');
    await fs.mkdirp(fallbackDir);
    effectiveCwd = fallbackDir;
    logger.info(`Black-box mode: using workspace ${effectiveCwd}`);
  }

  // Resolve model endpoint
  const endpoint: ResolvedModelEndpoint = resolveModelFromProfile(modelTier, modelProfile);
  const apiUrl = endpoint.base_url
    ? `${endpoint.base_url}/v1/chat/completions`
    : 'http://localhost:8000/v1/chat/completions';

  const apiKey = endpoint.api_key
    ? endpoint.api_key
    : endpoint.api_key_env
      ? (process.env[endpoint.api_key_env] ?? 'none')
      : 'none';

  logger.info(`OpenAI executor: model=${endpoint.model}, url=${apiUrl}`);
  logger.info(`Working directory: ${effectiveCwd}`);

  // Build tools
  const tools = buildToolDefinitions();

  // Initialize conversation
  const messages: OpenAIMessage[] = [
    {
      role: 'system',
      content: `You are a security analysis agent. You have access to tools for running commands, reading/writing files, and saving deliverables. Work methodically to complete the task. When you are done, say "DONE" in your final message.\n\nWorking directory: ${effectiveCwd}`,
    },
    {
      role: 'user',
      content: fullPrompt,
    },
  ];

  let turnCount = 0;
  let lastTextResult: string | null = null;
  let consecutiveErrors = 0;
  let totalTokens = 0;

  try {
    while (turnCount < MAX_TURNS) {
      turnCount++;

      // Call the model
      const response = await callChatCompletion(apiUrl, apiKey, endpoint.model, messages, tools, logger);

      if (!response) {
        consecutiveErrors++;
        if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
          throw new Error(`${MAX_CONSECUTIVE_ERRORS} consecutive API errors`);
        }
        // Add a brief pause before retrying
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      consecutiveErrors = 0;
      totalTokens += response.usage?.total_tokens ?? 0;

      const choice = response.choices[0];
      if (!choice) {
        throw new Error('Empty response from model');
      }

      const assistantMsg = choice.message;
      const textContent = assistantMsg.content ?? '';
      const toolCalls = assistantMsg.tool_calls ?? [];

      // Log turn to buffer for live dashboard
      if (turnBuffer) {
        const label = agentName ?? description;
        const parts: string[] = [];
        if (textContent) parts.push(textContent.slice(0, 150));
        for (const tc of toolCalls) {
          const fnArgs = tc.function.arguments.slice(0, 80);
          parts.push(`🔧 ${tc.function.name}: ${fnArgs}`);
        }
        const ts = new Date().toISOString();
        turnBuffer.push(`[${ts}] Turn ${turnCount} (${label}): ${parts.join(' | ').slice(0, 250)}`);
      }

      logger.info(`Turn ${turnCount}: ${textContent.slice(0, 80)}${toolCalls.length > 0 ? ` [${toolCalls.length} tool calls]` : ''}`);

      // Build assistant message for conversation
      const assistantMessage: OpenAIMessage = {
        role: 'assistant',
        content: textContent || null,
      };
      if (toolCalls.length > 0) {
        assistantMessage.tool_calls = toolCalls;
      }
      messages.push(assistantMessage);

      // If no tool calls, the model is done
      if (toolCalls.length === 0) {
        lastTextResult = textContent;
        break;
      }

      // Execute each tool call and add results
      for (const toolCall of toolCalls) {
        let parsedArgs: Record<string, unknown>;
        try {
          parsedArgs = JSON.parse(toolCall.function.arguments);
        } catch {
          parsedArgs = { raw: toolCall.function.arguments };
        }

        const result = await executeTool(
          toolCall.function.name,
          parsedArgs,
          effectiveCwd,
          logger
        );

        messages.push({
          role: 'tool',
          tool_call_id: toolCall.id,
          content: result,
        });
      }

      // Check if the model said "DONE" in its text
      if (textContent.includes('DONE') && toolCalls.length === 0) {
        lastTextResult = textContent;
        break;
      }
    }

    const duration = timer.stop();

    logger.info(`Agent completed: ${turnCount} turns, ${totalTokens} tokens, ${duration}ms`);

    return {
      result: lastTextResult,
      success: true,
      duration,
      turns: turnCount,
      cost: 0, // Local model, no API cost
      model: endpoint.model,
    };
  } catch (error) {
    const duration = timer.stop();
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error(`Agent failed: ${err.message}`);

    return {
      error: err.message,
      errorType: err.constructor.name,
      success: false,
      duration,
      cost: 0,
      retryable: true,
    };
  }
}

// ── API Call ────────────────────────────────────────────────────

async function callChatCompletion(
  apiUrl: string,
  apiKey: string,
  model: string,
  messages: OpenAIMessage[],
  tools: OpenAITool[],
  logger: ActivityLogger
): Promise<OpenAIChatResponse | null> {
  try {
    const body = {
      model,
      messages,
      tools,
      tool_choice: 'auto' as const,
      max_tokens: 4096,
      temperature: 0.1,
      // Qwen3.5 specific: disable thinking for deterministic tool calling
      chat_template_kwargs: { enable_thinking: false },
    };

    // 10-minute timeout for large responses (e.g. writing deliverables with big context)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 600_000);

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      const errorText = await response.text();
      logger.error(`API error ${response.status}: ${errorText.slice(0, 500)}`);
      return null;
    }

    return await response.json() as OpenAIChatResponse;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    logger.error(`API call failed: ${msg}`);
    return null;
  }
}
